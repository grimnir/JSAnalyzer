# -*- coding: utf-8 -*-
"""
JS Analyzer - Results Panel
Features: Search filter (debounced), Copy button, Source filtering,
          Type column for Secrets, dup-count stats, CSV + JSON export.
"""

from javax.swing import (
    JPanel, JScrollPane, JTabbedPane, JButton, JLabel,
    JTable, JComboBox, JTextField, BorderFactory,
    JMenuItem, JPopupMenu, Timer as SwingTimer
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Font, Dimension, Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, KeyListener, KeyEvent
import json


class ResultsPanel(JPanel):
    """Results panel with search filter and copy functionality."""

    # Tab order: (display title, category key). Index matches tab index.
    _TABS = (
        ("Endpoints", "endpoints"),
        ("URLs", "urls"),
        ("Secrets", "secrets"),
        ("Emails", "emails"),
        ("Files", "files"),
        ("Dictionary", "dictionary"),
    )
    # Categories that track per-panel duplicate counts (Dictionary excluded).
    _DUP_CATEGORIES = ('endpoints', 'urls', 'secrets', 'emails', 'files')

    def __init__(self, callbacks, extender):
        JPanel.__init__(self)
        self.callbacks = callbacks
        self.extender = extender

        # Findings by category
        self.findings = {
            "endpoints": [],
            "urls": [],
            "secrets": [],
            "emails": [],
            "files": [],
            "dictionary": [],
        }

        # Duplicate counters (panel-level, for display)
        self.dup_counts = {k: 0 for k in self._DUP_CATEGORIES}

        # Panel-level seen sets for dup counting
        self._panel_seen = {k: set() for k in self._DUP_CATEGORIES}

        # Unique sources
        self.sources = set()

        self._init_ui()

    def _init_ui(self):
        """Build the UI."""
        self.setLayout(BorderLayout(5, 5))

        # ===== HEADER =====
        header = JPanel(BorderLayout(5, 0))
        header.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        # Left side - Title and stats
        left_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        left_panel.add(JLabel("JS Analyzer"))

        self.stats_label = JLabel("| E:0 | U:0 | S:0 (0 dup) | M:0 | F:0 | D:0")
        self.stats_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        left_panel.add(self.stats_label)
        header.add(left_panel, BorderLayout.WEST)

        # Right side - Controls
        controls = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 0))

        # Search box
        controls.add(JLabel("Search:"))
        self.search_field = JTextField(15)
        self.search_field.addKeyListener(SearchKeyListener(self))
        controls.add(self.search_field)

        # Source filter
        controls.add(JLabel("Source:"))
        self.source_filter = JComboBox(["All"])
        self.source_filter.setPreferredSize(Dimension(150, 25))
        self.source_filter.addActionListener(FilterAction(self))
        controls.add(self.source_filter)

        # Copy button
        copy_btn = JButton("Copy")
        copy_btn.addActionListener(CopyAction(self))
        controls.add(copy_btn)

        # Copy All button
        copy_all_btn = JButton("Copy All")
        copy_all_btn.addActionListener(CopyAllAction(self))
        controls.add(copy_all_btn)

        # Clear button
        clear_btn = JButton("Clear")
        clear_btn.addActionListener(ClearAction(self))
        controls.add(clear_btn)

        # Export JSON button (legacy)
        export_btn = JButton("Export JSON")
        export_btn.addActionListener(ExportAction(self))
        controls.add(export_btn)

        # Export CSV button
        export_csv_btn = JButton("Export CSV")
        export_csv_btn.addActionListener(ExportCsvAction(self))
        controls.add(export_csv_btn)

        header.add(controls, BorderLayout.EAST)
        self.add(header, BorderLayout.NORTH)

        # ===== TABS WITH TABLES =====
        self.tabs = JTabbedPane()

        self.tables = {}
        self.models = {}

        categories = [
            ("Endpoints", "endpoints", ["Value", "Source"]),
            ("URLs", "urls", ["Value", "Source"]),
            ("Secrets", "secrets", ["Type", "Value", "Source"]),
            ("Emails", "emails", ["Value", "Source"]),
            ("Files", "files", ["Value", "Source"]),
            ("Dictionary", "dictionary", ["Template", "Source"]),
        ]

        for title, key, columns in categories:
            panel = JPanel(BorderLayout())
            model = NonEditableTableModel(columns, 0)
            self.models[key] = model

            table = JTable(model)
            table.setAutoCreateRowSorter(True)
            table.setFont(Font("Monospaced", Font.PLAIN, 12))

            if key == "secrets":
                table.getColumnModel().getColumn(0).setPreferredWidth(130)  # Type
                table.getColumnModel().getColumn(1).setPreferredWidth(400)  # Value
                table.getColumnModel().getColumn(2).setPreferredWidth(150)  # Source
            else:
                table.getColumnModel().getColumn(0).setPreferredWidth(500)
                table.getColumnModel().getColumn(1).setPreferredWidth(150)

            self.tables[key] = table

            # Per-tab right-click popup for CSV export
            popup = JPopupMenu()
            tab_csv_item = JMenuItem("Export this tab as CSV")
            tab_csv_item.addActionListener(_TabCsvAction(self, key))
            popup.add(tab_csv_item)
            table.setComponentPopupMenu(popup)

            scroll = JScrollPane(table)
            panel.add(scroll, BorderLayout.CENTER)

            self.tabs.addTab(title + " (0)", panel)

        self.add(self.tabs, BorderLayout.CENTER)

    def add_findings(self, new_findings, source_name):
        """Add new findings."""
        if source_name and source_name not in self.sources:
            self.sources.add(source_name)
            self.source_filter.addItem(source_name)

        for finding in new_findings:
            category = finding.get("category", "")
            if category in self.findings:
                v_key = finding.get("value", "")
                if category in self._panel_seen:
                    if v_key in self._panel_seen[category]:
                        self.dup_counts[category] = self.dup_counts.get(category, 0) + 1
                        continue
                    self._panel_seen[category].add(v_key)
                entry = {
                    "value": v_key,
                    "source": finding.get("source", source_name),
                    "label": finding.get("label", ""),
                }
                self.findings[category].append(entry)

        self._refresh_tables()

    def _refresh_tables(self):
        """Refresh tables with current filters."""
        selected_source = str(self.source_filter.getSelectedItem())
        search_text = self.search_field.getText().lower().strip()

        for i, (title, key) in enumerate(self._TABS):
            model = self.models[key]
            model.setRowCount(0)

            count = 0
            for item in self.findings.get(key, []):
                # Source filter
                if selected_source != "All" and item.get("source") != selected_source:
                    continue

                # Search filter
                if search_text:
                    value_lower = item.get("value", "").lower()
                    if search_text not in value_lower:
                        continue

                if key == "secrets":
                    model.addRow([
                        item.get("label", ""),
                        item.get("value", ""),
                        item.get("source", ""),
                    ])
                else:
                    model.addRow([
                        item.get("value", ""),
                        item.get("source", ""),
                    ])
                count += 1

            self.tabs.setTitleAt(i, "%s (%d)" % (title, count))

        self._update_stats()

    def _update_stats(self):
        """Update stats label."""
        e = len(self.findings.get("endpoints", []))
        u = len(self.findings.get("urls", []))
        s = len(self.findings.get("secrets", []))
        sd = self.dup_counts.get("secrets", 0)
        m = len(self.findings.get("emails", []))
        f = len(self.findings.get("files", []))
        d = len(self.findings.get("dictionary", []))
        self.stats_label.setText(
            "| E:%d | U:%d | S:%d (%d dup) | M:%d | F:%d | D:%d" % (e, u, s, sd, m, f, d))

    def _get_current_table(self):
        """Get the currently visible table."""
        key = self._get_current_key()
        return self.tables.get(key) if key else None

    def _get_current_key(self):
        """Get the current category key."""
        idx = self.tabs.getSelectedIndex()
        if 0 <= idx < len(self._TABS):
            return self._TABS[idx][1]
        return None

    def copy_selected(self):
        """Copy selected row's value to clipboard."""
        table = self._get_current_table()
        if not table:
            return

        row = table.getSelectedRow()
        if row >= 0:
            model_row = table.convertRowIndexToModel(row)
            key = self._get_current_key()
            # For secrets: col 0 = Type, col 1 = Value; copy Value
            col = 1 if key == "secrets" else 0
            value = table.getModel().getValueAt(model_row, col)
            self._copy_to_clipboard(str(value))

    def copy_all_visible(self):
        """Copy all visible values in current tab to clipboard."""
        table = self._get_current_table()
        if not table:
            return

        key = self._get_current_key()
        col = 1 if key == "secrets" else 0
        model = table.getModel()
        values = []
        for i in range(model.getRowCount()):
            values.append(str(model.getValueAt(i, col)))

        if values:
            self._copy_to_clipboard("\n".join(values))

    def _copy_to_clipboard(self, text):
        """Copy text to system clipboard."""
        try:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(text), None)
        except Exception:
            pass

    def clear_all(self):
        """Clear all results."""
        for key in self.findings:
            self.findings[key] = []
        self.dup_counts = {k: 0 for k in self._DUP_CATEGORIES}
        self._panel_seen = {k: set() for k in self._DUP_CATEGORIES}
        self.sources = set()

        self.source_filter.removeAllItems()
        self.source_filter.addItem("All")
        self.search_field.setText("")

        self.extender.clear_results()
        self._refresh_tables()

    def export_all(self):
        """Export all findings to JSON."""
        from javax.swing import JFileChooser
        from java.io import File

        chooser = JFileChooser()
        chooser.setSelectedFile(File("js_findings.json"))

        if chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()

            export = {
                "endpoints": [f["value"] for f in self.findings.get("endpoints", [])],
                "urls": [f["value"] for f in self.findings.get("urls", [])],
                "secrets": [f["value"] for f in self.findings.get("secrets", [])],
                "emails": [f["value"] for f in self.findings.get("emails", [])],
                "files": [f["value"] for f in self.findings.get("files", [])],
                "dictionary": [f["value"] for f in self.findings.get("dictionary", [])],
            }

            fp = open(path, 'w')
            try:
                json.dump(export, fp, indent=2)
            finally:
                fp.close()

    def _export_csv(self, category=None):
        """Export findings to CSV (codecs.open, utf-8).

        If category is None, export all categories.
        Columns: category, value, source, label
        """
        import codecs
        import sys as _sys
        import os as _os
        from javax.swing import JFileChooser, JOptionPane
        from java.io import File

        # Ensure csv_utils is importable (ui/ dir is on sys.path via ext_dir)
        _ui_dir = _os.path.dirname(_os.path.abspath(__file__))
        if _ui_dir not in _sys.path:
            _sys.path.insert(0, _ui_dir)
        from csv_utils import format_csv_row

        chooser = JFileChooser()
        default_name = (category or 'all') + '_findings.csv'
        chooser.setSelectedFile(File(default_name))
        if chooser.showSaveDialog(self) != JFileChooser.APPROVE_OPTION:
            return

        path = chooser.getSelectedFile().getAbsolutePath()

        cats = [category] if category else list(self.findings.keys())

        try:
            with codecs.open(path, 'w', 'utf-8') as fp:
                fp.write('category,value,source,label\n')
                for cat in cats:
                    for item in self.findings.get(cat, []):
                        row = format_csv_row(
                            cat,
                            item.get('value', ''),
                            item.get('source', ''),
                            item.get('label', ''),
                        )
                        fp.write(row + '\n')
        except Exception as ex:
            JOptionPane.showMessageDialog(self,
                'CSV export failed: ' + str(ex),
                'Export Error',
                JOptionPane.ERROR_MESSAGE)
            return

        JOptionPane.showMessageDialog(self,
            'Exported to ' + path,
            'Export Complete',
            JOptionPane.INFORMATION_MESSAGE)


class NonEditableTableModel(DefaultTableModel):
    def __init__(self, columns, rows):
        DefaultTableModel.__init__(self, columns, rows)

    def isCellEditable(self, row, column):
        return False


class _DebounceTimerAction(ActionListener):
    """Fires _refresh_tables once after 150 ms of typing silence."""
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel._refresh_tables()
        # Timer is setRepeats(False) so it fires exactly once


class SearchKeyListener(KeyListener):
    """Starts/restarts a 150 ms debounce timer on each keystroke."""
    def __init__(self, panel):
        self.panel = panel
        self._timer = SwingTimer(150, _DebounceTimerAction(panel))
        self._timer.setRepeats(False)

    def keyPressed(self, event):
        pass

    def keyReleased(self, event):
        if self._timer.isRunning():
            self._timer.restart()
        else:
            self._timer.start()

    def keyTyped(self, event):
        pass


class FilterAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel._refresh_tables()


class CopyAction(ActionListener):
    """Copy selected row."""
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel.copy_selected()


class CopyAllAction(ActionListener):
    """Copy all visible rows."""
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel.copy_all_visible()


class ClearAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel.clear_all()


class ExportAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel.export_all()


class ExportCsvAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel

    def actionPerformed(self, event):
        self.panel._export_csv(category=None)


class _TabCsvAction(ActionListener):
    def __init__(self, panel, category):
        self.panel = panel
        self.category = category

    def actionPerformed(self, event):
        self.panel._export_csv(category=self.category)
