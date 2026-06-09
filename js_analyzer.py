# -*- coding: utf-8 -*-
"""
JS Analyzer - Burp Suite Extension
Thin adapter: IBurpExtender, IContextMenuFactory, ITab.
All detection logic lives in js_analyzer_engine (pure Python, no Burp deps).
"""

from burp import IBurpExtender, IContextMenuFactory, ITab

from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.util import ArrayList
from java.io import PrintWriter

import sys
import os
import inspect

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
from js_analyzer_engine import JSAnalyzerEngine


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
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

        # Pure detection engine -- stateless per call
        self._engine = JSAnalyzerEngine()

        # Initialize UI
        self.panel = ResultsPanel(callbacks, self)

        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

        self._log('JS Analyzer loaded - Right-click JS responses to analyze')

    def _log(self, msg):
        self._stdout.println('[JS Analyzer] ' + str(msg))

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
        except Exception as e:
            self._log('Menu error: ' + str(e))
        return menu

    def analyze_response(self, message_info):
        """Analyze a response using the pure engine and push findings to the UI."""
        response = message_info.getResponse()
        if not response:
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
            return

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

        # secrets -- values are {'type', 'value', 'masked'};
        # store the masked form in seen_values and display (per existing behavior)
        for secret in result['secrets']:
            masked = secret['masked']
            finding = self._add_finding('secrets', masked, source_name)
            if finding:
                new_findings.append(finding)

        # dictionary -- Phase 0: always [] so this loop is a no-op until Phase 1
        for template, evidence in result['dictionary']:
            finding = self._add_finding('dictionary', template, source_name)
            if finding:
                new_findings.append(finding)

        if new_findings:
            self._log('Found %d new items' % len(new_findings))
            self.panel.add_findings(new_findings, source_name)
        else:
            self._log('No new findings')

    def _add_finding(self, category, value, source):
        """Add a finding to the global list if not already seen (dedup by key)."""
        key = category + ':' + value
        if key in self.seen_values:
            return None
        self.seen_values.add(key)
        finding = {
            'category': category,
            'value': value,
            'source': source,
        }
        self.all_findings.append(finding)
        return finding

    def clear_results(self):
        self.all_findings = []
        self.seen_values = set()

    def get_all_findings(self):
        return self.all_findings


class AnalyzeAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation

    def actionPerformed(self, event):
        try:
            messages = self.invocation.getSelectedMessages()
            for msg in messages:
                try:
                    self.extender.analyze_response(msg)
                except Exception as e:
                    self.extender._log('Error analyzing response: ' + str(e))
        except Exception as e:
            if self.extender:
                self.extender._log('Action error: ' + str(e))
