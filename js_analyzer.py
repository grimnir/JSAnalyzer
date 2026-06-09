# -*- coding: utf-8 -*-
"""
JS Analyzer - Burp Suite Extension
Thin adapter: IBurpExtender, IContextMenuFactory, ITab.
All detection logic lives in js_analyzer_engine (pure Python, no Burp deps).
"""

from burp import IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener

from javax.swing import JMenuItem, SwingUtilities
from java.awt.event import ActionListener
from java.util import ArrayList
from java.io import PrintWriter
from java.lang import Runnable as JRunnable, Thread as JThread

import sys
import os
import inspect
import codecs

DEDUP_CAP = 50000
_BODY_CAP = 2 * 1024 * 1024   # 2 MB

_SETTINGS_PREFIX = 'jsa_'

_SETTINGS_DEFAULTS_STR = {
    'threads': '10',
    'rate': '20',
    'timeout': '10',
    'method': 'GET',
    'destructive': 'false',
    'inscope': 'true',
    'wordlist': '',
}

# Add extension directory to path so Jython can find js_analyzer_engine.py
# and ui/results_panel.py at the same level.
try:
    _frame = inspect.currentframe()
    if _frame and hasattr(_frame, 'f_code'):
        ext_dir = os.path.dirname(os.path.abspath(_frame.f_code.co_filename))
    else:
        ext_dir = os.getcwd()
except Exception:
    ext_dir = os.getcwd()

if ext_dir and ext_dir not in sys.path:
    sys.path.insert(0, ext_dir)

from ui.results_panel import ResultsPanel
from ui.active_scan_panel import DiscoveryPanel, DiscoveryConfig
from js_analyzer_engine import JSAnalyzerEngine, cast_setting, SETTING_KEYS


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):
    """JS Analyzer -- thin Burp adapter delegating all detection to JSAnalyzerEngine."""

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName('JS Analyzer')

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # Results storage (dedup and persistence live here, NOT in the engine)
        self.all_findings = []
        self.seen_values = set()

        # Discovery engine reference (set when a scan starts)
        self._discovery_engine = None
        self._discovery_panel  = None

        # Load wordlist (api.txt next to this file) for dictionary matching.
        # codecs.open gives explicit UTF-8 decoding under both Py2 and Py3.
        # Missing/unreadable file is non-fatal: engine runs with an empty index.
        wordlist_lines = []
        try:
            _wl_path = os.path.join(ext_dir, 'api.txt')
            _wl_fh = codecs.open(_wl_path, 'r', 'utf-8')
            try:
                wordlist_lines = _wl_fh.readlines()
            finally:
                _wl_fh.close()
            self._log('Loaded wordlist: %d lines from api.txt' % len(wordlist_lines))
        except IOError:
            self._log('api.txt not found - dictionary matching disabled')
        except Exception as _wl_err:
            self._log('api.txt load error: ' + str(_wl_err))

        # Pure detection engine -- stateless per call
        self._engine = JSAnalyzerEngine(wordlist=wordlist_lines if wordlist_lines else None)

        # Initialize UI
        self.panel = ResultsPanel(callbacks, self)

        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        callbacks.registerExtensionStateListener(self)

        # Load persisted settings (falls back to defaults if first run)
        self._settings = {}
        for k in SETTING_KEYS:
            self._settings[k] = self._load_setting(k)
        self._log('Settings loaded: threads=%s rate=%s timeout=%s method=%s' % (
            self._settings['threads'], self._settings['rate'],
            self._settings['timeout'], self._settings['method']))

        # Load persisted discovery config
        self._discovery_config = DiscoveryConfig()
        self._discovery_config.apply_from_settings(self._load_setting_kv)

        # Resolve bundled wordlist path
        self._api_txt = os.path.join(ext_dir, 'api.txt')

        # Create the JS Probe tab ONCE at load (always visible, not lazy)
        self._discovery_panel = DiscoveryPanel(callbacks, self, self._discovery_config)
        callbacks.addSuiteTab(_DiscoveryTab(self._discovery_panel))

        self._log('JS Analyzer loaded - Right-click JS responses to analyze')

    def _log(self, msg):
        self._stdout.println('[JS Analyzer] ' + str(msg))

    def _load_setting(self, key):
        """Load setting from Burp persistent store; fall back to default string then cast."""
        raw = self._callbacks.loadExtensionSetting(_SETTINGS_PREFIX + key)
        if raw is None:
            raw = _SETTINGS_DEFAULTS_STR.get(key, '')
        return cast_setting(key, raw)

    def _load_setting_kv(self, key, default):
        """Load a persisted setting by bare key; returns default if absent.
        Used by DiscoveryConfig.apply_from_settings (two-arg signature).
        """
        try:
            val = self._callbacks.loadExtensionSetting(key)
            if val is None:
                return default
            if isinstance(default, bool):
                return val == 'true'
            if isinstance(default, int):
                return int(val)
            return val
        except Exception:
            return default

    def _save_setting(self, key, value):
        """Persist a setting. value is Python-typed; stored as string.
        Accepts both bare keys (used by DiscoveryConfig.persist) and
        prefixed keys (legacy). Always stores as string.
        """
        try:
            self._callbacks.saveExtensionSetting(key, str(value))
        except Exception:  # nosec B110 - best-effort settings persistence
            pass

    def extensionUnloaded(self):
        """IExtensionStateListener -- shut down active scan thread pool on unload."""
        if self._discovery_engine is not None:
            try:
                self._discovery_engine.shutdown()
            except Exception:  # nosec B110 - best-effort thread-pool cleanup on unload
                pass
        self._log('JS Analyzer unloaded.')

    def getTabCaption(self):
        return 'JS Analyzer'

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu = ArrayList()
        try:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                item = JMenuItem('Analyze JS with JS Analyzer')
                item.addActionListener(AnalyzeAction(self, invocation))
                menu.add(item)
                if len(messages) == 1:
                    probe_item = JMenuItem('Probe endpoints with wordlist')
                    probe_item.addActionListener(ProbeAction(self, invocation))
                    menu.add(probe_item)
        except Exception as e:
            self._log('Menu error: ' + str(e))
        return menu

    def analyze_response(self, message_info):
        """Analyze a response using the pure engine and push findings to the UI."""
        response = message_info.getResponse()
        if not response:
            self._log('Skipped: selected item has NO response. '
                      'Right-click an item that has a response (e.g. in Proxy > HTTP history or Repeater).')
            return

        # Determine display name for the source file
        try:
            req_info = self._helpers.analyzeRequest(message_info)
            url = str(req_info.getUrl())
            source_name = url.split('/')[-1].split('?')[0] if '/' in url else url
            if len(source_name) > 40:
                source_name = source_name[:40] + '...'
        except Exception:
            url = 'Unknown'
            source_name = 'Unknown'

        # Extract body as string
        resp_info = self._helpers.analyzeResponse(response)
        body_offset = resp_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])

        if len(body) < 50:
            self._log('Skipped %s: response body too small (%d bytes; need >= 50)' % (source_name, len(body)))
            return

        if len(body) > _BODY_CAP:
            self._log('Body truncated to 2 MB for analysis (was %d bytes)' % len(body))
            body = body[:_BODY_CAP]

        self._log('Analyzing: ' + source_name)

        # Delegate all detection to the pure engine
        result = self._engine.analyze(body, source_name)

        new_findings = []

        # endpoints, urls, emails, files -- values are plain strings
        for category in ('endpoints', 'urls', 'emails', 'files'):
            for value in result[category]:
                finding = self._add_finding(category, value, source_name)
                if finding:
                    new_findings.append(finding)

        # secrets -- dedup key on raw value; display masked form; thread label=type
        for secret in result['secrets']:
            raw_value = secret['value']
            masked = secret['masked']
            label = secret['type']
            finding = self._add_finding('secrets', raw_value, source_name, label=label)
            if finding:
                # Override stored value with masked form for display
                finding['value'] = masked
                new_findings.append(finding)

        # dictionary -- (template, evidence) tuples; store the template value
        for template, evidence in result['dictionary']:
            finding = self._add_finding('dictionary', template, source_name)
            if finding:
                new_findings.append(finding)

        if new_findings:
            self._log('Found %d new items' % len(new_findings))
            # Marshal UI update to EDT (analyze_response runs on a worker thread)
            SwingUtilities.invokeLater(
                _AddFindingsRunnable(self.panel, list(new_findings), source_name))
        else:
            self._log('No new findings')

    def _add_finding(self, category, value, source, label=None):
        """Add a finding if not duplicate.

        Dedup key: category + raw value (never masked).
        label: pattern label string (e.g. 'AWS Key'), stored for display.
        DEDUP_CAP guard: once seen_values reaches 50000, log once and drop.
        """
        if len(self.seen_values) >= DEDUP_CAP:
            if not getattr(self, '_dedup_cap_logged', False):
                self._log('DEDUP_CAP reached (%d); dropping further findings.' % DEDUP_CAP)
                self._dedup_cap_logged = True
            return None
        key = category + ':' + value
        if key in self.seen_values:
            return None
        self.seen_values.add(key)
        finding = {
            'category': category,
            'value': value,
            'source': source,
            'label': label or '',
        }
        self.all_findings.append(finding)
        return finding

    def clear_results(self):
        self.all_findings = []
        self.seen_values = set()

    def get_all_findings(self):
        return self.all_findings


class _AnalyzeRunnable(JRunnable):
    """Worker-thread body for one analysis run. Never runs on EDT."""
    def __init__(self, extender, messages):
        self.extender = extender
        self.messages = messages

    def run(self):
        for msg in self.messages:
            try:
                self.extender.analyze_response(msg)
            except Exception as e:
                self.extender._log('Error analyzing response: ' + str(e))


class _AddFindingsRunnable(JRunnable):
    """EDT body: push new findings into the results panel.

    Module-level (not a nested closure) for reliable Jython 2.7 behaviour --
    matches the Runnable pattern used everywhere else in the extension.
    """
    def __init__(self, panel, findings, source):
        self.panel = panel
        self.findings = findings
        self.source = source

    def run(self):
        self.panel.add_findings(self.findings, self.source)


class AnalyzeAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        """Called on EDT -- immediately hand off to a worker thread."""
        try:
            messages = list(self.invocation.getSelectedMessages())
            self.extender._log('Analyze requested: %d message(s)' % len(messages))
            t = JThread(_AnalyzeRunnable(self.extender, messages))
            t.setDaemon(True)
            t.setName('JSAnalyzer-worker')
            t.start()
        except Exception as e:
            if self.extender:
                self.extender._log('Action error: ' + str(e))


class ProbeAction(ActionListener):
    """Context menu action: Probe endpoints with wordlist (WS2)."""

    def __init__(self, extender, invocation):
        self._extender   = extender
        self._invocation = invocation

    def actionPerformed(self, event):
        from javax.swing import JOptionPane
        from java.net import URL

        ext = self._extender
        try:
            messages = self._invocation.getSelectedMessages()
            if not messages or len(messages) != 1:
                return
            msg = messages[0]

            # --- 1. Derive base URL ---
            req_info = ext._helpers.analyzeRequest(msg)
            url_obj  = req_info.getUrl()
            scheme   = url_obj.getProtocol()
            host     = url_obj.getHost()
            port     = url_obj.getPort()
            if port == -1:
                base_url_str = '%s://%s' % (scheme, host)
            else:
                base_url_str = '%s://%s:%d' % (scheme, host, port)

            try:
                base_java_url = URL(base_url_str)
            except Exception as e:
                JOptionPane.showMessageDialog(None,
                    'Invalid base URL: ' + base_url_str, 'JS Analyzer', JOptionPane.ERROR_MESSAGE)
                return

            # --- 2. Scope check BEFORE dialog ---
            if ext._discovery_config.in_scope:
                if not ext._callbacks.isInScope(base_java_url):
                    JOptionPane.showMessageDialog(None,
                        'Target %s is NOT in scope.\n'
                        'Add it to scope or disable "in-scope only" in Discovery config.' % base_url_str,
                        'JS Analyzer -- Out of Scope', JOptionPane.WARNING_MESSAGE)
                    return

            # --- 3. Load + filter wordlist ---
            from ui.active_scan_panel import WordlistLoader, DiscoveryEngine
            loader = WordlistLoader()
            wl_path = ext._discovery_config.wordlist or ext._api_txt
            try:
                paths = loader.load(wl_path)
            except IOError as e:
                JOptionPane.showMessageDialog(None,
                    'Cannot read wordlist: ' + str(e), 'JS Analyzer', JOptionPane.ERROR_MESSAGE)
                return

            if not ext._discovery_config.destructive:
                paths = loader.filter_destructive(paths)

            if not paths:
                JOptionPane.showMessageDialog(None,
                    'No paths remain after filtering.',
                    'JS Analyzer', JOptionPane.INFORMATION_MESSAGE)
                return

            cfg = ext._discovery_config
            destructive_label = 'YES (destructive paths INCLUDED)' if cfg.destructive else 'no'

            # --- 4. Consent dialog ---
            msg_text = (
                'JS Analyzer -- Active Endpoint Probe\n\n'
                'Host:        %s\n'
                'Paths:       %d (post-filter)\n'
                'Method:      %s\n'
                'Threads:     %d\n'
                'Rate:        %d req/s\n'
                'Timeout:     %d s\n'
                'Destructive: %s\n'
                'In-scope:    %s\n\n'
                'WARNING: This sends real HTTP %s requests to the target.\n'
                'GET requests can still have side effects (caching, logging, etc.).\n\n'
                'Proceed?'
            ) % (
                base_url_str, len(paths), cfg.method,
                cfg.threads, cfg.rate, cfg.timeout,
                destructive_label,
                'yes' if cfg.in_scope else 'no (all hosts)',
                cfg.method,
            )

            choice = JOptionPane.showConfirmDialog(
                None, msg_text,
                'JS Analyzer -- Confirm Probe',
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            )
            if choice != JOptionPane.YES_OPTION:
                return

            # --- 5. Build DiscoveryEngine and start (panel created at load) ---
            engine = DiscoveryEngine(
                ext._callbacks, ext._helpers, msg, paths, cfg, ext._discovery_panel
            )
            ext._discovery_engine = engine
            ext._discovery_panel.set_engine(engine)
            engine.start()

        except Exception as e:
            ext._log('ProbeAction error: ' + str(e))
            import traceback
            ext._log(traceback.format_exc())


class _DiscoveryTab(ITab):
    """Minimal ITab wrapper for the DiscoveryPanel.

    MUST extend burp.ITab: Jython passes this to callbacks.addSuiteTab(ITab),
    and a plain object would raise TypeError (the 'JS Probe' tab never appears).
    """

    def __init__(self, panel):
        self._panel = panel

    def getTabCaption(self):
        return 'JS Probe'

    def getUiComponent(self):
        return self._panel
