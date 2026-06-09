# -*- coding: utf-8 -*-
"""
ui/active_scan_panel.py -- WS2 Active Scanner panel for JS Analyzer.

DiscoveryConfig  -- settings with defaults and ceiling enforcement.
WordlistLoader   -- loads and sanitises api.txt using pure _sanitize().
DiscoveryPanel   -- JPanel: table / progressbar / start-stop / filter / export.
DiscoveryEngine  -- ThreadPoolExecutor dispatcher.
ProbeTask        -- per-path Runnable.

Burp/Swing only: no python3 unit tests possible for this file.
Manual verification steps are listed at the bottom of each section.
"""

# --- Java/Swing imports (Jython 2.7 only) ---
from javax.swing import (
    JPanel, JScrollPane, JButton, JLabel, JTable, JComboBox,
    JProgressBar, JTextField, JSplitPane, JOptionPane, JCheckBox,
    BorderFactory, SwingUtilities, Timer as SwingTimer, JPopupMenu, JMenuItem,
    JFileChooser
)
from java.awt import Toolkit
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Dimension, Color
from java.awt.event import ActionListener
from java.io import PrintWriter
import sys
import os

# Pure helper -- zero java imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from discovery_logic import _sanitize, is_destructive, is_interesting, soft404_fingerprint, build_request_line


# ---------------------------------------------------------------------------
# DiscoveryConfig -- §3.2 defaults and ceilings
# ---------------------------------------------------------------------------
class DiscoveryConfig(object):
    """Holds active-scan settings. Ceilings enforced in setters."""

    THREAD_CEILING = 50
    RATE_CEILING   = 100

    def __init__(self):
        self.threads        = 10
        self.rate           = 20        # req/s
        self.timeout        = 10        # seconds per request
        self.method         = 'GET'
        self.destructive    = False
        self.in_scope       = True
        self.wordlist       = ''        # path to wordlist file; '' = use bundled api.txt
        self.show_all       = False     # Feature B: record all non-soft-404 responses
        self.add_to_sitemap = False     # Feature C: addToSiteMap() on recorded results

    def set_threads(self, v):
        self.threads = max(1, min(int(v), self.THREAD_CEILING))

    def set_rate(self, v):
        self.rate = max(1, min(int(v), self.RATE_CEILING))

    def set_timeout(self, v):
        self.timeout = max(1, int(v))

    def apply_from_settings(self, load_fn):
        """Load persisted values via load_fn(key, default)."""
        self.set_threads(load_fn('jsa_threads', 10))
        self.set_rate(load_fn('jsa_rate', 20))
        self.set_timeout(load_fn('jsa_timeout', 10))
        raw_method          = str(load_fn('jsa_method', 'GET')).upper()
        self.method         = raw_method if raw_method in ('GET', 'HEAD') else 'GET'
        self.destructive    = str(load_fn('jsa_destructive', 'false')) == 'true'
        self.in_scope       = str(load_fn('jsa_inscope', 'true')) == 'true'
        self.wordlist       = str(load_fn('jsa_wordlist', ''))
        self.show_all       = str(load_fn('jsa_showall', 'false')) == 'true'
        self.add_to_sitemap = str(load_fn('jsa_sitemap', 'false')) == 'true'

    def persist(self, save_fn):
        """Persist current values via save_fn(key, value)."""
        save_fn('jsa_threads',     str(self.threads))
        save_fn('jsa_rate',        str(self.rate))
        save_fn('jsa_timeout',     str(self.timeout))
        save_fn('jsa_method',      self.method)
        save_fn('jsa_destructive', 'true' if self.destructive else 'false')
        save_fn('jsa_inscope',     'true' if self.in_scope else 'false')
        save_fn('jsa_wordlist',    self.wordlist)
        save_fn('jsa_showall',     'true' if self.show_all else 'false')
        save_fn('jsa_sitemap',     'true' if self.add_to_sitemap else 'false')


# ---------------------------------------------------------------------------
# WordlistLoader -- §3.3
# ---------------------------------------------------------------------------
class WordlistLoader(object):
    """Loads a file and returns sanitised paths via _sanitize()."""

    def load(self, filepath):
        """Read *filepath* and return list of sanitised paths.

        Raises IOError if the file cannot be read.
        """
        fp = open(filepath, 'r')
        try:
            lines = fp.read().splitlines()
        finally:
            fp.close()
        return _sanitize(lines)

    def filter_destructive(self, paths):
        """Return paths with destructive entries removed."""
        return [p for p in paths if not is_destructive(p)]


# ---------------------------------------------------------------------------
# Non-editable table model helper
# ---------------------------------------------------------------------------
class _NonEditableModel(DefaultTableModel):
    def __init__(self, cols, rows):
        DefaultTableModel.__init__(self, cols, rows)

    def isCellEditable(self, row, col):
        return False


# ---------------------------------------------------------------------------
# DiscoveryPanel -- JPanel shell
# ---------------------------------------------------------------------------
class DiscoveryPanel(JPanel):
    """Active scan results panel.

    Columns: Path | Status | Length | Content-Type | Redirect
    Controls: Start / Stop / status-class filter / Export CSV / JProgressBar
    """

    _COLUMNS = ['Path', 'Status', 'Length', 'Content-Type', 'Redirect']

    def __init__(self, callbacks, extender, config):
        JPanel.__init__(self)
        self._callbacks = callbacks
        self._extender  = extender
        self._helpers   = callbacks.getHelpers()
        self.config     = config
        self._engine    = None    # set via set_engine()

        self._init_ui()

    # --- UI construction ---

    def _init_ui(self):
        self.setLayout(BorderLayout(5, 5))

        # --- top controls ---
        top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))

        self._start_btn = JButton('Start')
        self._start_btn.addActionListener(_StartAction(self))
        top.add(self._start_btn)

        self._stop_btn = JButton('Stop')
        self._stop_btn.setEnabled(False)
        self._stop_btn.addActionListener(_StopAction(self))
        top.add(self._stop_btn)

        top.add(JLabel('Status filter:'))
        self._status_filter = JComboBox(['All', '2xx', '3xx', '4xx', '5xx'])
        self._status_filter.addActionListener(_FilterAction(self))
        top.add(self._status_filter)

        self._export_btn = JButton('Export CSV')
        self._export_btn.addActionListener(_ExportCSVAction(self))
        top.add(self._export_btn)

        self._status_lbl = JLabel('Idle')
        top.add(self._status_lbl)

        # --- config row ---
        cfg_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        cfg_row.add(JLabel('Threads:'))
        self._threads_field = JTextField(str(self.config.threads), 4)
        cfg_row.add(self._threads_field)

        cfg_row.add(JLabel('Rate/s:'))
        self._rate_field = JTextField(str(self.config.rate), 4)
        cfg_row.add(self._rate_field)

        cfg_row.add(JLabel('Timeout(s):'))
        self._timeout_field = JTextField(str(self.config.timeout), 4)
        cfg_row.add(self._timeout_field)

        cfg_row.add(JLabel('Method:'))
        self._method_combo = JComboBox(['GET', 'HEAD'])
        self._method_combo.setSelectedItem(
            self.config.method if self.config.method in ('GET', 'HEAD') else 'GET')
        cfg_row.add(self._method_combo)

        self._destructive_cb = JCheckBox('Allow destructive', self.config.destructive)
        cfg_row.add(self._destructive_cb)

        self._inscope_cb = JCheckBox('In-scope only', self.config.in_scope)
        cfg_row.add(self._inscope_cb)

        self._showall_cb = JCheckBox('Show all (incl. 404)', self.config.show_all)
        cfg_row.add(self._showall_cb)

        self._sitemap_cb = JCheckBox('Add to Site map', self.config.add_to_sitemap)
        cfg_row.add(self._sitemap_cb)

        save_cfg_btn = JButton('Save config')
        save_cfg_btn.addActionListener(_SaveConfigAction(self))
        cfg_row.add(save_cfg_btn)

        # --- wordlist row ---
        wl_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        wl_row.add(JLabel('Wordlist:'))
        wl_initial = os.path.basename(self.config.wordlist) if self.config.wordlist else '(default api.txt)'
        self._wordlist_lbl = JLabel(wl_initial)
        wl_row.add(self._wordlist_lbl)
        load_wl_btn = JButton('Load wordlist...')
        load_wl_btn.addActionListener(_LoadWordlistAction(self))
        wl_row.add(load_wl_btn)

        # Wrap top + cfg_row + wl_row in a single north panel
        north = JPanel(BorderLayout())
        north.add(top, BorderLayout.NORTH)
        cfg_and_wl = JPanel(BorderLayout())
        cfg_and_wl.add(cfg_row, BorderLayout.NORTH)
        cfg_and_wl.add(wl_row, BorderLayout.SOUTH)
        north.add(cfg_and_wl, BorderLayout.SOUTH)
        self.add(north, BorderLayout.NORTH)

        # --- progress bar ---
        self._progress = JProgressBar(0, 100)
        self._progress.setStringPainted(True)
        self._progress.setString('0 / 0')
        self.add(self._progress, BorderLayout.SOUTH)

        # --- table ---
        self._model = _NonEditableModel(self._COLUMNS, 0)
        self._table = JTable(self._model)
        self._table.setAutoCreateRowSorter(True)
        self._table.getColumnModel().getColumn(0).setPreferredWidth(350)
        self._table.getColumnModel().getColumn(1).setPreferredWidth(60)
        self._table.getColumnModel().getColumn(2).setPreferredWidth(70)
        self._table.getColumnModel().getColumn(3).setPreferredWidth(130)
        self._table.getColumnModel().getColumn(4).setPreferredWidth(200)

        # Right-click context menu: Send to Repeater / Intruder / Copy URL
        popup = JPopupMenu()
        repeater_item = JMenuItem('Send to Repeater')
        repeater_item.addActionListener(_SendToRepeaterAction(self))
        popup.add(repeater_item)
        intruder_item = JMenuItem('Send to Intruder')
        intruder_item.addActionListener(_SendToIntruderAction(self))
        popup.add(intruder_item)
        copy_url_item = JMenuItem('Copy URL')
        copy_url_item.addActionListener(_CopyURLAction(self))
        popup.add(copy_url_item)
        self._table.setComponentPopupMenu(popup)

        scroll = JScrollPane(self._table)
        self.add(scroll, BorderLayout.CENTER)

        # All rows storage (unfiltered)
        self._all_rows = []

    # --- public API used by DiscoveryEngine ---

    def set_engine(self, engine):
        self._engine = engine

    def set_wordlist_label(self, text):
        """Update the wordlist label (used by passive->active bridge)."""
        self._wordlist_lbl.setText(text)

    def set_status(self, text):
        """Update status label from EDT."""
        self._status_lbl.setText(text)

    def set_progress(self, done, total):
        """Update progress bar from EDT (shows probed/total and live hit count)."""
        found = len(self._all_rows)
        if total > 0:
            pct = int(float(done) / float(total) * 100)
            self._progress.setValue(pct)
            self._progress.setString('%d / %d  (%d found)' % (done, total, found))
        else:
            self._progress.setValue(0)
            self._progress.setString('0 / 0')

    def append_rows(self, rows):
        """Add rows (list of 5-tuples) to table from EDT."""
        filter_val = str(self._status_filter.getSelectedItem())
        for row in rows:
            self._all_rows.append(row)
            if self._matches_filter(row, filter_val):
                self._model.addRow(list(row))

    def _matches_filter(self, row, filter_val):
        if filter_val == 'All':
            return True
        try:
            st = int(row[1])
        except (TypeError, ValueError):
            return False
        if filter_val == '2xx' and 200 <= st < 300:
            return True
        if filter_val == '3xx' and 300 <= st < 400:
            return True
        if filter_val == '4xx' and 400 <= st < 500:
            return True
        if filter_val == '5xx' and 500 <= st < 600:
            return True
        return False

    def _reapply_filter(self):
        filter_val = str(self._status_filter.getSelectedItem())
        self._model.setRowCount(0)
        for row in self._all_rows:
            if self._matches_filter(row, filter_val):
                self._model.addRow(list(row))

    def on_scan_started(self, total):
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self.set_progress(0, total)
        self.set_status('Running...')
        self._all_rows = []
        self._model.setRowCount(0)

    def on_scan_finished(self):
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self.set_status('Done. %d results.' % len(self._all_rows))

    def export_csv(self):
        """Export current table rows to a CSV file chosen via JFileChooser."""
        from javax.swing import JFileChooser
        from java.io import File
        import codecs
        chooser = JFileChooser()
        chooser.setSelectedFile(File('discovery_results.csv'))
        if chooser.showSaveDialog(self) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        fp = codecs.open(path, 'w', 'utf-8')
        try:
            fp.write('Path,Status,Length,Content-Type,Redirect\n')
            for row in self._all_rows:
                escaped = ['"%s"' % str(c).replace('"', '""') for c in row]
                fp.write(','.join(escaped) + '\n')
        finally:
            fp.close()


# ---------------------------------------------------------------------------
# Inner action listeners (EDT-safe, no blocking calls)
# ---------------------------------------------------------------------------
class _StartAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        if self._panel._engine:
            self._panel._engine.start()

class _StopAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        if self._panel._engine:
            self._panel._engine.stop()

class _FilterAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        self._panel._reapply_filter()

class _ExportCSVAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        self._panel.export_csv()


# ---------------------------------------------------------------------------
# DiscoveryEngine -- ThreadPoolExecutor + token-bucket dispatcher
# ---------------------------------------------------------------------------
# Java concurrency imports (Jython 2.7)
from java.util.concurrent import (
    ThreadPoolExecutor, TimeUnit, ArrayBlockingQueue, Executors
)
from java.util.concurrent.atomic import AtomicBoolean, AtomicInteger
from java.util.concurrent import ConcurrentLinkedQueue
from java.lang import Thread as JThread, Runnable, System
from java.util import UUID


class DiscoveryEngine(object):
    """Dispatcher + thread pool for active endpoint probing.

    Usage:
        engine = DiscoveryEngine(callbacks, helpers, msg, paths, config, panel)
        panel.set_engine(engine)
        engine.start()   # non-blocking; spawns dispatcher thread
        engine.stop()    # sets stop flag; pool drains within ~1 request cycle
    """

    def __init__(self, callbacks, helpers, msg, paths, config, panel):
        self._callbacks = callbacks
        self._helpers   = helpers
        self._msg       = msg           # IHttpRequestResponse template
        self._paths     = paths         # list[str] sanitised paths
        self._config    = config
        self._panel     = panel

        n = config.threads
        queue_cap = max(n * 4, 1)
        self._pool = ThreadPoolExecutor(
            n, n, 0, TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(queue_cap),
            ThreadPoolExecutor.CallerRunsPolicy()
        )
        # Separate single-thread pool for per-request timeout wrapping
        self._timeout_pool = Executors.newCachedThreadPool()

        self._stop         = AtomicBoolean(False)
        self._error_streak = AtomicInteger(0)
        self._queue        = ConcurrentLinkedQueue()  # metadata dicts -> Timer drains
        self._done         = AtomicInteger(0)
        self._total        = len(paths)
        # Live tally so the operator can see WHY the table is (or isn't) filling
        self._found        = AtomicInteger(0)   # interesting results
        self._soft404      = AtomicInteger(0)   # suppressed as soft-404 baseline
        self._errors       = AtomicInteger(0)   # timeouts / connection errors

        # Soft-404 baselines: list of fingerprint tuples
        self._baselines    = []

        # javax.swing.Timer (EDT) drains queue -> table
        self._drain_timer  = SwingTimer(250, _DrainAction(self._queue, panel, self))
        self._drain_timer.setRepeats(True)

    def start(self):
        """Spawn dispatcher thread; non-blocking."""
        self._stop.set(False)
        SwingUtilities.invokeLater(_PanelStartRunnable(self._panel, self._total))
        self._drain_timer.start()
        t = JThread(_DispatcherRunnable(self))
        t.setDaemon(True)
        t.setName('jsa-discovery-dispatcher')
        t.start()

    def stop(self):
        """Signal stop; drain pool."""
        self._stop.set(True)
        self._pool.shutdownNow()
        self._drain_timer.stop()
        SwingUtilities.invokeLater(_PanelFinishRunnable(self._panel))

    def shutdown(self):
        """Called from extensionUnloaded -- hard stop."""
        self._stop.set(True)
        self._pool.shutdownNow()
        self._timeout_pool.shutdownNow()
        try:
            self._pool.awaitTermination(5, TimeUnit.SECONDS)
        except Exception:  # nosec B110 - InterruptedException during pool await is expected
            pass
        self._drain_timer.stop()

    def _calibrate(self):
        """Probe 2 random paths to build soft-404 baselines."""
        for _ in range(2):
            rand_path = '/' + str(UUID.randomUUID()).replace('-', '')
            try:
                rr = self._probe(rand_path)
                if rr is None:
                    continue
                resp    = rr.getResponse()
                ri      = self._helpers.analyzeResponse(resp)
                status  = ri.getStatusCode()
                offset  = ri.getBodyOffset()
                body    = self._helpers.bytesToString(resp[offset:])
                fp      = soft404_fingerprint(status, len(body), body)
                self._baselines.append(fp)
                if status == 200:
                    SwingUtilities.invokeLater(
                        _StatusRunnable(self._panel,
                                        'Warning: server returns 200 for random paths (soft-404)'))
            except Exception:  # nosec B110 - best-effort UI warning push
                pass

    def build_request_bytes(self, path):
        """Build raw HTTP request bytes for *path* reusing the engine's template.

        Rewrites the request line, strips body-related headers, and returns
        the bytes suitable for makeHttpRequest / sendToRepeater / sendToIntruder.
        Raises on error (callers handle).
        """
        req_info = self._helpers.analyzeRequest(self._msg)
        headers  = list(req_info.getHeaders())   # MUST copy -- unmodifiable
        # Rewrite request line (headers[0]) with the configured path
        headers[0] = build_request_line(headers[0], path)
        # Feature A: replace method token with configured method (GET/HEAD only;
        # clamp anything that slipped through to GET so POST/PUT/DELETE never fire).
        parts = headers[0].split(' ')
        configured_method = self._config.method.upper()
        if configured_method not in ('GET', 'HEAD'):
            configured_method = 'GET'
        parts[0] = configured_method
        headers[0] = ' '.join(parts)
        # Strip body-related headers
        to_remove = [h for h in headers
                     if h.lower().startswith(
                         ('content-type:', 'content-length:', 'transfer-encoding:'))]
        for h in to_remove:
            headers.remove(h)
        return self._helpers.buildHttpMessage(headers, None)

    def _probe(self, path):
        """Build and fire a single GET request; returns IHttpRequestResponse or None."""
        try:
            req_bytes = self.build_request_bytes(path)
            # Use IHttpService overload (returns IHttpRequestResponse)
            rr = self._callbacks.makeHttpRequest(self._msg.getHttpService(), req_bytes)
            return rr
        except Exception:
            return None

    def _is_soft404(self, fingerprint):
        return fingerprint in self._baselines

    def record_result(self, meta):
        """Called from ProbeTask worker thread -- push an interesting result to the queue.

        Progress (_done) is incremented per-probe in ProbeTask.run (every outcome),
        NOT here -- otherwise the progress bar only moves on interesting hits and
        looks frozen on targets that 404 most paths.
        """
        self._queue.add(meta)
        self._found.incrementAndGet()

    def record_error(self):
        self._errors.incrementAndGet()
        streak = self._error_streak.incrementAndGet()
        if streak >= 20:
            self._error_streak.set(0)
            SwingUtilities.invokeLater(
                _StatusRunnable(self._panel,
                                'Auto-paused: 20 consecutive errors. Retrying in 5s.'))
            try:
                JThread.sleep(5000)
            except Exception:  # nosec B110 - InterruptedException during auto-pause sleep is expected
                pass


# ---------------------------------------------------------------------------
# Dispatcher Runnable -- runs on dedicated non-EDT thread
# ---------------------------------------------------------------------------
class _DispatcherRunnable(Runnable):
    def __init__(self, engine):
        self._engine = engine

    def run(self):
        e  = self._engine
        ns_per_token = int(1e9 / float(e._config.rate))  # nanoseconds per token

        # Soft-404 calibration before dispatching
        e._calibrate()

        last_send_ns = 0
        for path in e._paths:
            if e._stop.get():
                break
            # Token-bucket: sleep until next allowed send time
            while True:
                now = System.nanoTime()
                elapsed = now - last_send_ns
                if elapsed >= ns_per_token:
                    break
                sleep_ms = (ns_per_token - elapsed) // 1000000
                if sleep_ms > 0:
                    try:
                        JThread.sleep(sleep_ms)
                    except Exception:  # nosec B110 - InterruptedException during rate-limit sleep is expected
                        pass
            last_send_ns = System.nanoTime()
            task = ProbeTask(e, path)
            try:
                e._pool.submit(task)
            except Exception:  # nosec B110 - task rejected after stop/shutdown is expected
                pass

        # Wait for pool to drain then signal UI
        e._pool.shutdown()
        try:
            e._pool.awaitTermination(60, TimeUnit.SECONDS)
        except Exception:  # nosec B110 - InterruptedException during pool await is expected
            pass
        e._drain_timer.stop()
        SwingUtilities.invokeLater(_PanelFinishRunnable(e._panel))


# ---------------------------------------------------------------------------
# ProbeTask -- per-path Runnable submitted to thread pool
# ---------------------------------------------------------------------------
class ProbeTask(Runnable):
    """One GET probe. Stop flag checked first line."""

    def __init__(self, engine, path):
        self._engine = engine
        self._path   = path

    def run(self):
        e = self._engine
        if e._stop.get():
            return
        try:
            # Wrap blocking makeHttpRequest in Callable for timeout
            call = _ProbeCallable(e, self._path)
            future = e._timeout_pool.submit(call)
            try:
                rr = future.get(e._config.timeout, TimeUnit.SECONDS)
            except Exception:
                future.cancel(True)
                e.record_error()
                return

            if rr is None:
                e.record_error()
                return

            resp   = rr.getResponse()
            ri     = e._helpers.analyzeResponse(resp)
            status = int(ri.getStatusCode())
            offset = ri.getBodyOffset()
            body   = e._helpers.bytesToString(resp[offset:])
            ctype  = str(ri.getInferredMimeType())
            length = len(resp) - offset

            # Location header check
            headers_list = list(ri.getHeaders())
            location = ''
            for h in headers_list:
                if h.lower().startswith('location:'):
                    location = h[9:].strip()
                    break
            has_loc = bool(location)

            fp = soft404_fingerprint(status, length, body)

            # Soft-404 suppression always takes priority (even in show_all mode)
            # so a catch-all target doesn't flood the table with identical rows.
            if e._is_soft404(fp):
                e._soft404.incrementAndGet()
                return

            # Feature B: in show_all mode, bypass is_interesting() so 404 and
            # other non-interesting responses (with distinct fingerprints) are
            # still recorded.  Without show_all, only interesting codes pass.
            if not (is_interesting(status, has_loc) or e._config.show_all):
                return

            meta = {
                'path':     self._path,
                'status':   status,
                'length':   length,
                'ctype':    ctype,
                'redirect': location,
            }
            e.record_result(meta)
            # Feature C: add to Burp Site map (only recorded results, never
            # soft-404s or dropped probes).
            if e._config.add_to_sitemap:
                try:
                    e._callbacks.addToSiteMap(rr)
                except Exception:  # nosec B110 - best-effort site-map addition
                    pass
            e._error_streak.set(0)

        except Exception:
            e.record_error()
        finally:
            # Count EVERY completed probe (hit, miss, soft-404, drop, error) so the
            # progress bar reflects real scan progress -- not just interesting hits.
            e._done.incrementAndGet()


# ---------------------------------------------------------------------------
# Callable wrapper for timeout (submitted to cached pool)
# ---------------------------------------------------------------------------
from java.util.concurrent import Callable as JCallable


class _ProbeCallable(JCallable):
    def __init__(self, engine, path):
        self._engine = engine
        self._path   = path

    def call(self):
        return self._engine._probe(self._path)


# ---------------------------------------------------------------------------
# Swing Timer drain action (EDT)
# ---------------------------------------------------------------------------
class _DrainAction(ActionListener):
    def __init__(self, queue, panel, engine):
        self._queue  = queue
        self._panel  = panel
        self._engine = engine

    def actionPerformed(self, event):
        rows = []
        count = 0
        while count < 500:
            item = self._queue.poll()
            if item is None:
                break
            rows.append((
                item.get('path', ''),
                item.get('status', ''),
                item.get('length', ''),
                item.get('ctype', ''),
                item.get('redirect', ''),
            ))
            count += 1
        if rows:
            self._panel.append_rows(rows)
        e = self._engine
        done = e._done.get()
        self._panel.set_progress(done, e._total)
        # Live tally -> status label, so an empty table is self-explanatory:
        #   misses (e.g. 404) = done - hits - soft404 - errors
        self._panel.set_status(
            'probed %d/%d | hits %d | soft404 %d | errors %d'
            % (done, e._total, e._found.get(), e._soft404.get(), e._errors.get()))


# ---------------------------------------------------------------------------
# Small EDT Runnables
# ---------------------------------------------------------------------------
class _PanelStartRunnable(Runnable):
    def __init__(self, panel, total):
        self._panel = panel
        self._total = total

    def run(self):
        self._panel.on_scan_started(self._total)


class _PanelFinishRunnable(Runnable):
    def __init__(self, panel):
        self._panel = panel

    def run(self):
        self._panel.on_scan_finished()


class _StatusRunnable(Runnable):
    def __init__(self, panel, text):
        self._panel = panel
        self._text  = text

    def run(self):
        self._panel.set_status(self._text)


# ---------------------------------------------------------------------------
# _SaveConfigAction -- persists DiscoveryConfig from panel fields
# ---------------------------------------------------------------------------
class _SaveConfigAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        p   = self._panel
        cfg = p.config
        try:
            cfg.set_threads(p._threads_field.getText().strip())
        except Exception:  # nosec B110 - invalid threads field falls back to current value
            pass
        try:
            cfg.set_rate(p._rate_field.getText().strip())
        except Exception:  # nosec B110 - invalid rate field falls back to current value
            pass
        try:
            cfg.set_timeout(p._timeout_field.getText().strip())
        except Exception:  # nosec B110 - invalid timeout field falls back to current value
            pass
        cfg.destructive = p._destructive_cb.isSelected()
        cfg.in_scope    = p._inscope_cb.isSelected()
        # Feature A: method selector (GET/HEAD only; clamp anything else to GET)
        raw_method  = str(p._method_combo.getSelectedItem()).upper()
        cfg.method  = raw_method if raw_method in ('GET', 'HEAD') else 'GET'
        # Feature B: show-all mode
        cfg.show_all = p._showall_cb.isSelected()
        # Feature C: add to site map
        cfg.add_to_sitemap = p._sitemap_cb.isSelected()
        # Persist via extender's _save_setting
        extender = p._extender
        cfg.persist(extender._save_setting)
        p.set_status('Config saved.')


# ---------------------------------------------------------------------------
# _LoadWordlistAction -- opens JFileChooser; updates config.wordlist + label
# ---------------------------------------------------------------------------
class _LoadWordlistAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self._panel) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        self._panel.config.wordlist = path
        # Persist immediately
        try:
            self._panel._extender._save_setting('jsa_wordlist', path)
        except Exception:  # nosec B110 - best-effort persistence
            pass
        # An explicitly chosen file overrides any passive-bridge wordlist
        self._panel._extender._custom_wordlist = None
        label = os.path.basename(path)
        self._panel._wordlist_lbl.setText(label)
        self._panel.set_status('Wordlist set: ' + label)


# ---------------------------------------------------------------------------
# Popup helpers: resolve selected path from table
# ---------------------------------------------------------------------------
def _get_selected_path_and_engine(panel):
    """Return (path, engine, svc) for the selected table row, or (None, None, None)."""
    view_row = panel._table.getSelectedRow()
    if view_row < 0:
        panel.set_status('Select a result row first.')
        return None, None, None
    if panel._engine is None:
        panel.set_status('Run a probe first.')
        return None, None, None
    model_row = panel._table.convertRowIndexToModel(view_row)
    path = str(panel._model.getValueAt(model_row, 0))
    svc = panel._engine._msg.getHttpService()
    return path, panel._engine, svc


# ---------------------------------------------------------------------------
# _SendToRepeaterAction
# ---------------------------------------------------------------------------
class _SendToRepeaterAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        path, engine, svc = _get_selected_path_and_engine(self._panel)
        if path is None:
            return
        try:
            req = engine.build_request_bytes(path)
            host = svc.getHost()
            port = svc.getPort()
            use_https = str(svc.getProtocol()).lower() == 'https'
            self._panel._callbacks.sendToRepeater(host, port, use_https, req, 'JSP ' + path)
            self._panel.set_status('Sent to Repeater: ' + path)
        except Exception as e:
            self._panel.set_status('Repeater error: ' + str(e))


# ---------------------------------------------------------------------------
# _SendToIntruderAction
# ---------------------------------------------------------------------------
class _SendToIntruderAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        path, engine, svc = _get_selected_path_and_engine(self._panel)
        if path is None:
            return
        try:
            req = engine.build_request_bytes(path)
            host = svc.getHost()
            port = svc.getPort()
            use_https = str(svc.getProtocol()).lower() == 'https'
            self._panel._callbacks.sendToIntruder(host, port, use_https, req)
            self._panel.set_status('Sent to Intruder: ' + path)
        except Exception as e:
            self._panel.set_status('Intruder error: ' + str(e))


# ---------------------------------------------------------------------------
# _CopyURLAction
# ---------------------------------------------------------------------------
class _CopyURLAction(ActionListener):
    def __init__(self, panel):
        self._panel = panel

    def actionPerformed(self, event):
        path, engine, svc = _get_selected_path_and_engine(self._panel)
        if path is None:
            return
        try:
            proto = str(svc.getProtocol())
            host = svc.getHost()
            port = svc.getPort()
            default_port = (443 if proto.lower() == 'https' else 80)
            if port == default_port or port == -1:
                url_str = '%s://%s%s' % (proto, host, path)
            else:
                url_str = '%s://%s:%d%s' % (proto, host, port, path)
            from java.awt.datatransfer import StringSelection
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(url_str), None)
            self._panel.set_status('Copied: ' + url_str)
        except Exception as e:
            self._panel.set_status('Copy error: ' + str(e))
