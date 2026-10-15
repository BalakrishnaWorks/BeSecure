from __future__ import annotations
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlsplit
from scanner import APP_VERSION, ScanError, scan_website

BG = "#08111f"
PANEL = "#101d30"
PANEL2 = "#17283f"
TEXT = "#edf5ff"
MUTED = "#9eb0c9"
TEAL = "#51e0c2"
AMBER = "#ffcb70"

class BeSecureApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"BeSecure Enterprise | v{APP_VERSION}")
        self.geometry("1220x820")
        self.minsize(980, 680)
        self.configure(bg=BG)
        self.report = None
        self.scanning = False
        self._style()
        self._build()

    def _style(self):
        s = ttk.Style(self)
        try: s.theme_use("clam")
        except tk.TclError: pass
        s.configure("TFrame", background=BG)
        s.configure("Panel.TFrame", background=PANEL)
        s.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 10))
        s.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        s.configure("Panel.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 10))
        s.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 27, "bold"))
        s.configure("Section.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 12, "bold"))
        s.configure("Score.TLabel", background=PANEL, foreground=TEAL, font=("Segoe UI", 36, "bold"))
        s.configure("TButton", font=("Segoe UI", 10, "bold"), padding=(12, 9))
        s.configure("Accent.TButton", background=TEAL, foreground="#06131b")
        s.map("Accent.TButton", background=[("disabled", "#426a69"), ("active", "#a6ffeb")])
        s.configure("Treeview", background=PANEL2, foreground=TEXT, fieldbackground=PANEL2, rowheight=31, font=("Segoe UI", 9))
        s.configure("Treeview.Heading", background="#223650", foreground=TEXT, font=("Segoe UI", 9, "bold"))
        s.map("Treeview", background=[("selected", "#285b65")])

    def _build(self):
        root = ttk.Frame(self, padding=22); root.pack(fill="both", expand=True)
        header = ttk.Frame(root); header.pack(fill="x")
        ttk.Label(header, text="◈  BeSecure", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text=f"ENTERPRISE SECURITY ASSESSMENT  •  v{APP_VERSION}", style="Muted.TLabel").pack(side="right", pady=(14, 0))
        ttk.Label(root, text="Evidence-led public checks and bounded authorized application mapping.", style="Muted.TLabel").pack(anchor="w", pady=(3, 16))

        top = ttk.Frame(root, style="Panel.TFrame", padding=17); top.pack(fill="x")
        ttk.Label(top, text="NEW ASSESSMENT", style="Section.TLabel").pack(anchor="w")
        ttk.Label(top, text="Enter only a hostname you own or are explicitly authorized to assess.", style="Panel.TLabel").pack(anchor="w", pady=(5, 10))
        row = ttk.Frame(top, style="Panel.TFrame"); row.pack(fill="x")
        self.target_var = tk.StringVar()
        self.target_entry = tk.Entry(row, textvariable=self.target_var, font=("Segoe UI", 12), bg="#081321", fg=TEXT,
            insertbackground=TEXT, relief="flat", highlightthickness=1, highlightbackground="#314761", highlightcolor=TEAL)
        self.target_entry.pack(side="left", fill="x", expand=True, ipady=11, padx=(0, 12))
        self.mode_var = tk.StringVar(value="passive")
        modebox = ttk.Frame(row, style="Panel.TFrame"); modebox.pack(side="left", padx=(0, 10))
        ttk.Radiobutton(modebox, text="Public Surface", variable=self.mode_var, value="passive").pack(anchor="w")
        ttk.Radiobutton(modebox, text="Authorized Expanded", variable=self.mode_var, value="authorized").pack(anchor="w")
        self.scan_btn = ttk.Button(row, text="Run assessment  →", style="Accent.TButton", command=self.start_scan)
        self.scan_btn.pack(side="right")
        self.auth_var = tk.BooleanVar(value=False)
        tk.Checkbutton(top, text="I own this domain or have explicit permission to assess it, including the selected mode.",
            variable=self.auth_var, bg=PANEL, fg=MUTED, activebackground=PANEL, activeforeground=TEXT,
            selectcolor=PANEL2, font=("Segoe UI", 9)).pack(anchor="w", pady=(11, 0))
        self.mode_note = tk.StringVar(value="Public Surface: root-page HTTPS/TLS, headers, redirects, and observable cookie checks. No login or exploitation.")
        ttk.Label(top, textvariable=self.mode_note, style="Panel.TLabel", wraplength=1100).pack(anchor="w", pady=(8, 0))
        self.mode_var.trace_add("write", self._mode_changed)

        self.status_var = tk.StringVar(value="Ready • No assessment has been run")
        ttk.Label(root, textvariable=self.status_var, style="Muted.TLabel").pack(anchor="w", pady=(12, 8))
        body = ttk.Frame(root); body.pack(fill="both", expand=True)
        left = ttk.Frame(body, style="Panel.TFrame", padding=17); left.pack(side="left", fill="y", padx=(0, 12))
        ttk.Label(left, text="ASSESSMENT SUMMARY", style="Section.TLabel").pack(anchor="w")
        self.score_var = tk.StringVar(value="—")
        ttk.Label(left, textvariable=self.score_var, style="Score.TLabel").pack(anchor="w", pady=(12, 0))
        ttk.Label(left, text="HEURISTIC SCORE / 100", style="Panel.TLabel").pack(anchor="w")
        self.summary_var = tk.StringVar(value="Run an assessment to view its findings.")
        ttk.Label(left, textvariable=self.summary_var, style="Panel.TLabel", wraplength=250, justify="left").pack(anchor="w", pady=(13, 12))
        ttk.Separator(left).pack(fill="x", pady=8)
        ttk.Label(left, text="RELEASE READINESS", style="Section.TLabel").pack(anchor="w", pady=(4, 8))
        ttk.Label(left, text="BeSecure does not issue a publish approval. Use findings alongside code review, dependency checks, authenticated testing, privacy review, and a documented release decision.",
            style="Panel.TLabel", wraplength=250, justify="left").pack(anchor="w")
        self.export_btn = ttk.Button(left, text="Export JSON report", command=self.export_report, state="disabled")
        self.export_btn.pack(anchor="w", pady=(17, 0))
        right = ttk.Frame(body, style="Panel.TFrame", padding=13); right.pack(side="left", fill="both", expand=True)
        ttk.Label(right, text="FINDINGS & EVIDENCE", style="Section.TLabel").pack(anchor="w", padx=4, pady=(2, 10))
        cols = ("severity", "status", "title", "confidence")
        self.tree = ttk.Treeview(right, columns=cols, show="headings", selectmode="browse")
        for col, label, width in [("severity", "SEVERITY", 92), ("status", "STATUS", 82), ("title", "CHECK / FINDING", 420), ("confidence", "CONFIDENCE", 90)]:
            self.tree.heading(col, text=label); self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_selected)
        self.detail = tk.Text(right, height=8, wrap="word", bg="#081321", fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 9), padx=11, pady=9)
        self.detail.pack(fill="x", pady=(10, 0)); self._set_detail("Select a row to view evidence and recommended remediation.")
        ttk.Label(root, text="LOCAL PROCESSING  •  NO DATABASE CONNECTION  •  NO ANALYTICS  •  REPORTS SAVED ONLY WHEN EXPORTED", style="Muted.TLabel").pack(anchor="w", pady=(12, 0))

    def _mode_changed(self, *_):
        if self.mode_var.get() == "authorized":
            self.mode_note.set("Authorized Expanded: bounded same-origin crawl (up to 25 pages / depth 2), header and cookie observations per page, form/resource inventory, mixed-content references, and fixed metadata checks. GET-only; no login, form submission, exploit payloads, or brute force.")
            self.scan_btn.configure(text="Run expanded checks  →")
        else:
            self.mode_note.set("Public Surface: root-page HTTPS/TLS, headers, redirects, and observable cookie checks. No login or exploitation.")
            self.scan_btn.configure(text="Run passive scan  →")

    def start_scan(self):
        if self.scanning: return
        if not self.auth_var.get():
            messagebox.showwarning("Authorization required", "Confirm that you own the domain or have explicit permission for the selected assessment mode."); return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Website required", "Enter a domain, for example https://example.com"); return
        self.scanning = True; self.scan_btn.configure(state="disabled"); self.export_btn.configure(state="disabled")
        self.tree.delete(*self.tree.get_children()); self._set_detail("Assessment running. Response bodies are used temporarily only for bounded same-origin HTML discovery in Expanded mode; page content and cookie values are not retained in the report.")
        self.status_var.set("Running bounded checks • Expanded mode may inspect up to 25 linked pages…")
        threading.Thread(target=self._worker, args=(target, self.mode_var.get()), daemon=True).start()

    def _worker(self, target, mode):
        try:
            report = scan_website(target, mode=mode)
            self.after(0, lambda: self._done(report, None))
        except ScanError as exc:
            self.after(0, lambda message=str(exc): self._done(None, message))
        except Exception:
            self.after(0, lambda: self._done(None, "Unexpected scan error. No report was created; check the local setup and try again."))

    def _done(self, report, error):
        self.scanning = False; self.scan_btn.configure(state="normal")
        if error:
            self.status_var.set("Assessment stopped • No report created")
            messagebox.showerror("Assessment could not complete", error); return
        self.report = report; self.score_var.set(str(report.score))
        review = sum(f.status == "Finding" for f in report.findings)
        status_label = {200: "200 OK", 206: "206 Partial Content (can be expected for Range requests)"}.get(report.http_status, str(report.http_status))
        mode_label = "Authorized Expanded" if report.assessment_mode == "authorized" else "Public Surface"
        self.summary_var.set(f"Mode: {mode_label}\nHTTP status: {status_label}\nChecks completed: {report.checks_completed}\nItems needing review: {review}\nTotal observations: {len(report.findings)}\nFinal URL: {report.final_url}\n\n{report.score_explanation}")
        for i, f in enumerate(report.findings):
            self.tree.insert("", "end", iid=str(i), values=(f.severity, f.status, f.title, f.confidence))
        self.status_var.set(f"Completed • {report.scanned_at_utc} • Review results with your security team")
        self.export_btn.configure(state="normal")
        self._set_detail("Select a row to view evidence and recommended remediation. Pass means only that the specific observable check passed.")

    def show_selected(self, _event=None):
        if not self.report: return
        selection = self.tree.selection()
        if not selection: return
        f = self.report.findings[int(selection[0])]
        self._set_detail(f"{f.title}\nSeverity: {f.severity}   Status: {f.status}   Confidence: {f.confidence}\n\nEvidence\n{f.evidence}\n\nRecommended remediation\n{f.recommendation}")

    def _set_detail(self, value):
        self.detail.configure(state="normal"); self.detail.delete("1.0", "end"); self.detail.insert("1.0", value); self.detail.configure(state="disabled")

    def export_report(self):
        if not self.report: return
        host = urlsplit(self.report.target).hostname or "website"
        path = filedialog.asksaveasfilename(title="Export BeSecure JSON report", defaultextension=".json",
            initialfile=f"besecure-{self.report.assessment_mode}-{host}.json", filetypes=[("JSON report", "*.json")])
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f: f.write(self.report.to_json())
            messagebox.showinfo("Report exported", "JSON report saved to the location you selected. Keep it private if it contains internal asset details.")
        except OSError:
            messagebox.showerror("Export failed", "Could not save the report. Check the selected folder permissions.")

if __name__ == "__main__":
    BeSecureApp().mainloop()
