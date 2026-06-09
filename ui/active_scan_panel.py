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
    BorderFactory, SwingUtilities, Timer as SwingTimer
)
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
        self.threads     = 10
        self.rate        = 20        # req/s
        self.timeout     = 10        # seconds per request
        self.method      = 'GET'
        self.destructive = False
        self.in_scope    = True
        self.wordlist    = ''        # path to wordlist file; '' = use bundled api.txt

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
        self.method      = str(load_fn('jsa_method', 'GET'))
        self.destructive = str(load_fn('jsa_destructive', 'false')) == 'true'
        self.in_scope    = str(load_fn('jsa_inscope', 'true')) == 'true'
        self.wordlist    = str(load_fn('jsa_wordlist', ''))

    def persist(self, save_fn):
        """Persist current values via save_fn(key, value)."""
        save_fn('jsa_threads',     str(self.threads))
        save_fn('jsa_rate',        str(self.rate))
        save_fn('jsa_timeout',     str(self.timeout))
        save_fn('jsa_method',      self.method)
        save_fn('jsa_destructive', 'true' if self.destructive else 'false')
        save_fn('jsa_inscope',     'true' if self.in_scope else 'false')
        save_fn('jsa_wordlist',    self.wordlist)


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

        self._destructive_cb = JCheckBox('Allow destructive', self.config.destructive)
        cfg_row.add(self._destructive_cb)

        self._inscope_cb = JCheckBox('In-scope only', self.config.in_scope)
        cfg_row.add(self._inscope_cb)

        save_cfg_btn = JButton('Save config')
        save_cfg_btn.addActionListener(_SaveConfigAction(self))
        cfg_row.add(save_cfg_btn)

        # Wrap top + cfg_row in a single north panel
        north = JPanel(BorderLayout())
        north.add(top, BorderLayout.NORTH)
        north.add(cfg_row, BorderLayout.SOUTH)
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
        scroll = JScrollPane(self._table)
        self.add(scroll, BorderLayout.CENTER)

        # All rows storage (unfiltered)
        self._all_rows = []

    # --- public API used by DiscoveryEngine ---

    def set_engine(self, engine):
        self._engine = engine

    def set_status(self, text):
        """Update status label from EDT."""
        self._status_lbl.setText(text)

    def set_progress(self, done, total):
        """Update progress bar from EDT."""
        if total > 0:
            pct = int(float(done) / float(total) * 100)
            self._progress.setValue(pct)
            self._progress.setString('%d / %d' % (done, total))
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

    def _probe(self, path):
        """Build and fire a single GET request; returns IHttpRequestResponse or None."""
        try:
            req_info = self._helpers.analyzeRequest(self._msg)
            headers  = list(req_info.getHeaders())   # MUST copy -- unmodifiable
            # Rewrite request line (headers[0])
            headers[0] = build_request_line(headers[0], path)
            # Strip body-related headers
            to_remove = [h for h in headers
                         if h.lower().startswith(
                             ('content-type:', 'content-length:', 'transfer-encoding:'))]
            for h in to_remove:
                headers.remove(h)
            req_bytes = self._helpers.buildHttpMessage(headers, None)
            # Use IHttpService overload (returns IHttpRequestResponse)
            rr = self._callbacks.makeHttpRequest(self._msg.getHttpService(), req_bytes)
            return rr
        except Exception:
            return None

    def _is_soft404(self, fingerprint):
        return fingerprint in self._baselines

    def record_result(self, meta):
        """Called from ProbeTask worker thread -- push to queue."""
        self._queue.add(meta)
        self._done.incrementAndGet()

    def record_error(self):
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

            if e._is_soft404(fp):
                return

            if not is_interesting(status, has_loc):
                return

            meta = {
                'path':     self._path,
                'status':   status,
                'length':   length,
                'ctype':    ctype,
                'redirect': location,
            }
            e.record_result(meta)
            e._error_streak.set(0)

        except Exception:
            e.record_error()


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
        done  = self._engine._done.get()
        total = self._engine._total
        self._panel.set_progress(done, total)


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
        # Persist via extender's _save_setting
        extender = p._extender
        cfg.persist(extender._save_setting)
        p.set_status('Config saved.')
