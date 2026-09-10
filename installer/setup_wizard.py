"""CBOMScan setup wizard.

Ships inside the distribution ZIP next to a `payload/` folder. Extract the ZIP
anywhere, run this, and it installs:

  * the CBOMScan desktop app (Electron)
  * the `cbomscan` command, on PATH, so it works from any terminal

and then offers to open the app.

Deliberately stdlib-only (tkinter, winreg, ctypes, subprocess). It must run on
a machine with no Python, no Node and nothing from this project installed, so
it cannot import the cbomscan package it is installing.
"""

from __future__ import annotations

import ctypes
import os
import queue
import shutil
import subprocess
import sys
import threading
import tkinter as tk
import winreg
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_NAME = "CBOMScan"
APP_TITLE = "CBOMScan Setup"
VERSION = "0.1.0"

ACCENT = "#1f6feb"
BG = "#f6f8fa"
MUTED = "#57606a"

DEFAULT_CLI_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME / "bin"
DEFAULT_APP_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Programs" / APP_NAME


# ------------------------------------------------------------------ payload --


def base_dir() -> Path:
    """Directory the wizard is running from (the extracted ZIP folder)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


def payload_dir() -> Path:
    return base_dir() / "payload"


def find_payload(pattern: str) -> Path | None:
    matches = sorted(payload_dir().glob(pattern))
    return matches[0] if matches else None


# ------------------------------------------------------------- install steps --


def run_app_installer(installer: Path, log) -> None:
    """Run the bundled Electron installer silently.

    electron-builder's NSIS package does the real work - install directory,
    Start Menu and desktop shortcuts, and the Add/Remove Programs entry - so
    the wizard drives it rather than reimplementing any of that.
    """
    log(f"Running {installer.name} (silent)...")
    result = subprocess.run(
        [str(installer), "/S"],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"The desktop app installer exited with code {result.returncode}.\n"
            f"{(result.stderr or result.stdout or '').strip()[:400]}"
        )
    log("Desktop app installed.")


def install_cli(engine: Path, cli_dir: Path, log) -> Path:
    """Copy the engine in as `cbomscan.exe` so the command matches its name."""
    cli_dir.mkdir(parents=True, exist_ok=True)
    target = cli_dir / "cbomscan.exe"

    if target.exists():
        # A running instance holds a lock; replacing on next boot is not worth
        # the complexity, so ask the user to close it instead.
        try:
            target.unlink()
        except PermissionError as exc:
            raise RuntimeError(
                f"{target} is in use. Close any running CBOMScan window or "
                "terminal and run setup again."
            ) from exc

    shutil.copy2(engine, target)
    log(f"Installed command line to {target}")
    return target


def add_to_path(directory: Path, log) -> bool:
    """Add a directory to the user's PATH, if it is not already there."""
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ) as key:
        try:
            current, kind = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            current, kind = "", winreg.REG_EXPAND_SZ

    entries = [p for p in current.split(os.pathsep) if p.strip()]
    if any(os.path.normcase(p.rstrip("\\")) == os.path.normcase(str(directory)) for p in entries):
        log("PATH already contains the CBOMScan directory.")
        return False

    updated = os.pathsep.join([*entries, str(directory)])
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Path", 0, kind or winreg.REG_EXPAND_SZ, updated)

    broadcast_environment_change()
    log(f"Added {directory} to your PATH.")
    return True


def broadcast_environment_change() -> None:
    """Tell running shells the environment changed, so new ones pick up PATH."""
    HWND_BROADCAST = 0xFFFF
    WM_SETTINGCHANGE = 0x001A
    SMTO_ABORTIFHUNG = 0x0002
    result = ctypes.c_ulong()
    ctypes.windll.user32.SendMessageTimeoutW(
        HWND_BROADCAST,
        WM_SETTINGCHANGE,
        0,
        ctypes.c_wchar_p("Environment"),
        SMTO_ABORTIFHUNG,
        5000,
        ctypes.byref(result),
    )


def record_install(app_exe: Path | None, cli_dir: Path) -> None:
    """Record where things went, so the CLI can find the app later."""
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\{APP_NAME}") as key:
        winreg.SetValueEx(key, "Version", 0, winreg.REG_SZ, VERSION)
        winreg.SetValueEx(key, "CliDir", 0, winreg.REG_SZ, str(cli_dir))
        if app_exe:
            winreg.SetValueEx(key, "AppExe", 0, winreg.REG_SZ, str(app_exe))


def locate_app() -> Path | None:
    """Find the installed desktop app executable."""
    candidates = [
        DEFAULT_APP_DIR / f"{APP_NAME}.exe",
        Path(os.environ.get("PROGRAMFILES", "")) / APP_NAME / f"{APP_NAME}.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"Software\{APP_NAME}") as key:
            value, _ = winreg.QueryValueEx(key, "AppExe")
            if Path(value).is_file():
                return Path(value)
    except OSError:
        pass
    return None


# ---------------------------------------------------------------- the wizard --


class SetupWizard(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        # Tall enough for the finish step, which is the densest: install
        # summary, PATH note, the launch prompt and its button, plus the footer.
        self.geometry("680x620")
        self.minsize(660, 600)
        self.configure(bg=BG)

        self.install_app = tk.BooleanVar(value=True)
        self.install_cli = tk.BooleanVar(value=True)
        self.add_path = tk.BooleanVar(value=True)
        self.cli_dir = tk.StringVar(value=str(DEFAULT_CLI_DIR))
        self.launch_after = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="")

        self._queue: queue.Queue = queue.Queue()
        self._log_lines: list[str] = []
        self.app_exe: Path | None = None
        self.installed_cli: Path | None = None

        self._style()

        tk.Label(
            self,
            text=f"{APP_NAME} Setup",
            font=("Segoe UI", 16, "bold"),
            bg=ACCENT,
            fg="white",
            anchor="w",
            padx=20,
            pady=13,
        ).pack(fill="x")

        # The footer is packed before the body and anchored to the bottom, so a
        # tall step can never squeeze the navigation buttons off the window.
        footer = tk.Frame(self, bg=BG, padx=26, pady=14)
        footer.pack(side="bottom", fill="x")
        self.back_btn = ttk.Button(footer, text="< Back", command=self.go_back)
        self.back_btn.pack(side="left")
        self.next_btn = ttk.Button(footer, text="Next >", command=self.go_next)
        self.next_btn.pack(side="right")
        self.cancel_btn = ttk.Button(footer, text="Cancel", command=self.on_cancel)
        self.cancel_btn.pack(side="right", padx=(0, 8))

        self.body = tk.Frame(self, bg=BG, padx=26, pady=18)
        self.body.pack(side="top", fill="both", expand=True)

        self.steps = [self.step_welcome, self.step_options, self.step_install, self.step_done]
        self.index = 0
        self.render()

    def _style(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("TButton", padding=(14, 6))

    # -------------------------------------------------------------- plumbing --

    def render(self) -> None:
        for child in self.body.winfo_children():
            child.destroy()
        self.back_btn.state(["!disabled"] if 0 < self.index < 2 else ["disabled"])
        self.next_btn.state(["!disabled"])
        self.next_btn.configure(text="Next >")
        self.steps[self.index]()

    def go_next(self) -> None:
        if self.index == 1 and not self.validate_options():
            return
        if self.index < len(self.steps) - 1:
            self.index += 1
            self.render()
            if self.index == 2:
                self.start_install()

    def go_back(self) -> None:
        if self.index > 0:
            self.index -= 1
            self.render()

    def on_cancel(self) -> None:
        if self.index == 2 and self.next_btn.instate(["disabled"]):
            if not messagebox.askyesno(APP_TITLE, "Installation is in progress. Cancel anyway?"):
                return
        self.destroy()

    def title_block(self, title: str, subtitle: str) -> None:
        tk.Label(self.body, text=title, font=("Segoe UI", 13, "bold"), bg=BG, anchor="w").pack(
            fill="x"
        )
        tk.Label(
            self.body,
            text=subtitle,
            font=("Segoe UI", 9),
            bg=BG,
            fg=MUTED,
            anchor="w",
            justify="left",
            wraplength=560,
        ).pack(fill="x", pady=(4, 14))

    # --------------------------------------------------------------- step 1 --

    def step_welcome(self) -> None:
        self.title_block(
            f"Welcome to {APP_NAME} {VERSION}",
            "CBOMScan inventories the cryptography in a codebase, scores it against the "
            "quantum threat, and exports a CycloneDX 1.7 Cryptographic Bill of Materials.",
        )

        tk.Label(
            self.body, text="This will install:", font=("Segoe UI", 10, "bold"), bg=BG, anchor="w"
        ).pack(fill="x", pady=(0, 6))

        for line in (
            "The CBOMScan desktop app, with Start Menu and desktop shortcuts",
            "The cbomscan command, available from any terminal",
        ):
            tk.Label(
                self.body, text=f"   •  {line}", font=("Segoe UI", 10), bg=BG, anchor="w"
            ).pack(fill="x", pady=2)

        tk.Label(
            self.body,
            text="\nNo Python, Node.js or internet connection is required - everything "
            "needed is included in this folder.",
            font=("Segoe UI", 9),
            bg=BG,
            fg=MUTED,
            anchor="w",
            justify="left",
            wraplength=560,
        ).pack(fill="x", pady=(10, 0))

        missing = self.missing_payload()
        if missing:
            tk.Label(
                self.body,
                text="\nMissing from this folder: "
                + ", ".join(missing)
                + "\nExtract the whole ZIP, keeping the payload folder next to this program.",
                font=("Segoe UI", 9),
                bg=BG,
                fg="#cf222e",
                anchor="w",
                justify="left",
                wraplength=560,
            ).pack(fill="x")
            self.next_btn.state(["disabled"])

    def missing_payload(self) -> list[str]:
        missing = []
        if not find_payload("*Setup*.exe"):
            missing.append("desktop app installer")
        if not find_payload("cbomscan.exe"):
            missing.append("cbomscan.exe engine")
        return missing

    # --------------------------------------------------------------- step 2 --

    def step_options(self) -> None:
        self.title_block(
            "Choose what to install",
            "Both components are recommended. The desktop app and the command line share "
            "the same engine, so results are identical either way.",
        )

        tk.Checkbutton(
            self.body,
            text="Desktop app  (Start Menu and desktop shortcuts)",
            variable=self.install_app,
            bg=BG,
            anchor="w",
            font=("Segoe UI", 10),
        ).pack(fill="x", pady=3)

        tk.Checkbutton(
            self.body,
            text="Command line  (the cbomscan command)",
            variable=self.install_cli,
            bg=BG,
            anchor="w",
            font=("Segoe UI", 10),
            command=self._sync_cli_controls,
        ).pack(fill="x", pady=3)

        self.path_check = tk.Checkbutton(
            self.body,
            text="Add cbomscan to my PATH, so it works from any terminal",
            variable=self.add_path,
            bg=BG,
            anchor="w",
            font=("Segoe UI", 10),
        )
        self.path_check.pack(fill="x", padx=(22, 0), pady=3)

        tk.Label(
            self.body,
            text="\nCommand line location",
            font=("Segoe UI", 10, "bold"),
            bg=BG,
            anchor="w",
        ).pack(fill="x", pady=(10, 4))

        row = tk.Frame(self.body, bg=BG)
        row.pack(fill="x")
        self.cli_entry = ttk.Entry(row, textvariable=self.cli_dir, font=("Segoe UI", 9))
        self.cli_entry.pack(side="left", fill="x", expand=True, ipady=3)
        self.browse_btn = ttk.Button(row, text="Browse...", command=self.browse_cli_dir)
        self.browse_btn.pack(side="left", padx=(8, 0))

        tk.Label(
            self.body,
            text="The desktop app installs to your user Programs folder and can be removed "
            "from Add or Remove Programs.",
            font=("Segoe UI", 9),
            bg=BG,
            fg=MUTED,
            anchor="w",
            justify="left",
            wraplength=560,
        ).pack(fill="x", pady=(8, 0))

        self._sync_cli_controls()

    def _sync_cli_controls(self) -> None:
        enabled = self.install_cli.get()
        state = "normal" if enabled else "disabled"
        self.path_check.configure(state=state)
        self.cli_entry.configure(state=state)
        self.browse_btn.state(["!disabled"] if enabled else ["disabled"])

    def browse_cli_dir(self) -> None:
        chosen = filedialog.askdirectory(title="Choose a folder for the cbomscan command")
        if chosen:
            self.cli_dir.set(chosen)

    def validate_options(self) -> bool:
        if not self.install_app.get() and not self.install_cli.get():
            messagebox.showwarning(APP_TITLE, "Select at least one component to install.")
            return False
        if self.install_cli.get() and not self.cli_dir.get().strip():
            messagebox.showwarning(APP_TITLE, "Choose a folder for the cbomscan command.")
            return False
        return True

    # --------------------------------------------------------------- step 3 --

    def step_install(self) -> None:
        self.title_block("Installing", "This takes a few moments.")
        self.next_btn.state(["disabled"])
        self.back_btn.state(["disabled"])

        self.progress = ttk.Progressbar(self.body, mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(0, 10))

        tk.Label(self.body, textvariable=self.status, font=("Segoe UI", 9), bg=BG, anchor="w").pack(
            fill="x"
        )

        self.log_box = tk.Text(
            self.body,
            height=11,
            font=("Consolas", 8),
            bg="white",
            fg=MUTED,
            relief="solid",
            borderwidth=1,
            wrap="word",
        )
        self.log_box.pack(fill="both", expand=True, pady=(10, 0))
        self.log_box.configure(state="disabled")

    def start_install(self) -> None:
        threading.Thread(target=self._install_worker, daemon=True).start()
        self.after(80, self._drain)

    def _install_worker(self) -> None:
        def log(message: str) -> None:
            self._queue.put(("log", message))

        def step(percent: int, message: str) -> None:
            self._queue.put(("step", (percent, message)))

        try:
            step(5, "Preparing...")

            if self.install_app.get():
                installer = find_payload("*Setup*.exe")
                if not installer:
                    raise RuntimeError("The desktop app installer is missing from payload/.")
                step(15, "Installing the desktop app...")
                run_app_installer(installer, log)
                step(65, "Desktop app installed.")
                self.app_exe = locate_app()
                log(f"App executable: {self.app_exe or 'not found'}")

            if self.install_cli.get():
                engine = find_payload("cbomscan.exe")
                if not engine:
                    raise RuntimeError("cbomscan.exe is missing from payload/.")
                step(75, "Installing the command line...")
                cli_dir = Path(self.cli_dir.get().strip())
                self.installed_cli = install_cli(engine, cli_dir, log)

                if self.add_path.get():
                    step(88, "Updating PATH...")
                    add_to_path(cli_dir, log)

            step(95, "Finishing up...")
            record_install(self.app_exe, Path(self.cli_dir.get().strip()))
            step(100, "Installation complete.")
            self._queue.put(("done", None))
        except Exception as exc:
            self._queue.put(("error", exc))

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "step":
                    percent, message = payload
                    self.progress["value"] = percent
                    self.status.set(message)
                    self._append_log(message)
                elif kind == "done":
                    self.index = 3
                    self.render()
                    return
                elif kind == "error":
                    self.status.set("Installation failed.")
                    self._append_log(f"ERROR: {payload}")
                    messagebox.showerror(APP_TITLE, f"Setup could not finish:\n\n{payload}")
                    self.back_btn.state(["!disabled"])
                    self.cancel_btn.configure(text="Close")
                    return
        except queue.Empty:
            pass
        self.after(80, self._drain)

    def _append_log(self, message: str) -> None:
        self._log_lines.append(message)
        self.log_box.configure(state="normal")
        self.log_box.insert("end", message + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    # --------------------------------------------------------------- step 4 --

    def step_done(self) -> None:
        self.title_block(
            "Setup complete",
            f"{APP_NAME} {VERSION} is installed and ready to use.",
        )

        rows = []
        if self.install_app.get():
            rows.append(("Desktop app", str(self.app_exe or DEFAULT_APP_DIR)))
        if self.install_cli.get():
            rows.append(("Command line", str(self.installed_cli or "")))
            if self.add_path.get():
                rows.append(("Terminal usage", "cbomscan scan <path>   (open a NEW terminal)"))

        for key, value in rows:
            row = tk.Frame(self.body, bg=BG)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=key, font=("Segoe UI", 9, "bold"), bg=BG, width=15, anchor="w").pack(
                side="left"
            )
            tk.Label(row, text=value, font=("Consolas", 8), bg=BG, fg=MUTED, anchor="w").pack(
                side="left", fill="x", expand=True
            )

        if self.install_cli.get() and self.add_path.get():
            tk.Label(
                self.body,
                text="\nPATH changes only apply to terminals opened from now on.",
                font=("Segoe UI", 9),
                bg=BG,
                fg=MUTED,
                anchor="w",
                wraplength=560,
                justify="left",
            ).pack(fill="x")

        if self.app_exe:
            tk.Label(
                self.body,
                text="\nWould you like to open CBOMScan now?",
                font=("Segoe UI", 10, "bold"),
                bg=BG,
                anchor="w",
            ).pack(fill="x", pady=(14, 6))

            tk.Checkbutton(
                self.body,
                text=f"Yes, open {APP_NAME} when I click Finish",
                variable=self.launch_after,
                bg=BG,
                anchor="w",
                font=("Segoe UI", 10),
            ).pack(fill="x")

            ttk.Button(self.body, text=f"Open {APP_NAME} now", command=self.launch_app).pack(
                anchor="w", pady=(12, 0)
            )

        self.back_btn.state(["disabled"])
        self.cancel_btn.configure(text="Close")
        self.next_btn.configure(text="Finish", command=self.finish)
        self.next_btn.state(["!disabled"])

    def launch_app(self) -> None:
        if not self.app_exe:
            messagebox.showinfo(APP_TITLE, "The desktop app was not installed.")
            return
        try:
            subprocess.Popen([str(self.app_exe)], close_fds=True)
            self.status.set(f"Started {self.app_exe.name}")
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not start the app:\n\n{exc}")

    def finish(self) -> None:
        if self.app_exe and self.launch_after.get():
            self.launch_app()
        self.destroy()


def silent_install(
    with_app: bool, with_cli: bool, with_path: bool, cli_dir: Path, log_path: Path | None
) -> int:
    """Unattended install, for deployment tooling and for testing the wizard.

    Runs exactly the same steps the GUI does. The wizard is a windowed binary
    with no console, so progress goes to a log file rather than stdout.
    """
    lines: list[str] = []

    def log(message: str) -> None:
        lines.append(message)
        if log_path:
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    log(f"{APP_NAME} {VERSION} unattended setup")
    log(f"payload: {payload_dir()}")

    app_exe = None
    try:
        if with_app:
            installer = find_payload("*Setup*.exe")
            if not installer:
                raise RuntimeError("desktop app installer missing from payload/")
            run_app_installer(installer, log)
            app_exe = locate_app()
            log(f"app executable: {app_exe or 'NOT FOUND'}")
            if not app_exe:
                raise RuntimeError("the app installer ran but no executable was found")

        if with_cli:
            engine = find_payload("cbomscan.exe")
            if not engine:
                raise RuntimeError("cbomscan.exe missing from payload/")
            installed = install_cli(engine, cli_dir, log)
            if with_path:
                add_to_path(cli_dir, log)
            log(f"cli executable: {installed}")

        record_install(app_exe, cli_dir)
        log("RESULT: PASS")
        return 0
    except Exception as exc:
        log(f"RESULT: FAIL - {exc}")
        return 1


def main() -> int:
    if sys.platform != "win32":
        print("The CBOMScan setup wizard runs on Windows.", file=sys.stderr)
        return 1

    argv = sys.argv[1:]
    if "--silent" in argv or "/S" in argv:

        def option(flag: str, default: str) -> str:
            return argv[argv.index(flag) + 1] if flag in argv else default

        return silent_install(
            with_app="--no-app" not in argv,
            with_cli="--no-cli" not in argv,
            with_path="--no-path" not in argv,
            cli_dir=Path(option("--dir", str(DEFAULT_CLI_DIR))),
            log_path=Path(option("--log", "")) if "--log" in argv else None,
        )

    SetupWizard().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
