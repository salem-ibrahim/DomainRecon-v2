"""Terminal UI toolkit for the DomainRecon interactive CLI (standard library only).

Three independent capabilities are detected once at start-up:

* ``layout``  - rich layout (banner, panels, tables, badges). Off when output is piped, injected
                by a caller/test, or ``DOMAINRECON_UI=plain``; then legacy line formats are kept.
* ``color``   - ANSI colour. Off with ``NO_COLOR`` or when the console cannot enable ANSI.
* ``unicode`` - box-drawing/symbol characters. Off for non-UTF-8 consoles or ``DOMAINRECON_UI=ascii``.

No third-party package is required. ``colorama`` (already a project requirement) is used only to
enable ANSI processing on legacy Windows consoles; without it a ctypes fallback is tried, and if
that fails colour is simply disabled. All text passed to the console is stripped of control
characters first, so remote-controlled values (titles, banners, DNS data) cannot inject terminal
escape sequences.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import textwrap
import threading
import time
from typing import Any, Callable, Iterable

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
CODES = {
    "reset": "0", "bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36",
    "white": "37", "grey": "90", "bright_red": "91", "bright_green": "92", "bright_yellow": "93", "bright_cyan": "96", "on_red": "41",
}
SEVERITY_STYLE = {"CRITICAL": ("bold", "white", "on_red"), "HIGH": ("bold", "bright_red"), "MEDIUM": ("yellow",), "LOW": ("cyan",), "INFO": ("grey",)}
KIND_STYLE = {"ACTIVE": ("bold", "magenta"), "PASSIVE": ("cyan",), "OFFLINE": ("blue",), "IMPORT": ("blue",), "ADMIN": ("grey",), "GUIDED": ("bold", "cyan")}
STATE_STYLE = {"READY": ("green",), "NEEDS": ("yellow",), "BLOCKED": ("red",), "OK": ("green",), "WARN": ("yellow",), "FAIL": ("red",), "INFO": ("grey",)}
_ERROR = re.compile(r"(?i)\b(failed|failure|error|could not|cannot|invalid|not found|blocked|refused|violation|not executable)\b")
_WARN = re.compile(r"(?i)\b(unavailable|skipped|not authorized|cancelled|deprecat\w*|unchanged|nothing was (run|started)|requires?|missing|not installed|declined)\b")
_SUCCESS = re.compile(r"(?i)\b(saved to|recorded|applied|completed|verified|generated|confirmed|finished)\b")
BANNER = (
    r" ____                        _       ____",
    r"|  _ \  ___  _ __ ___   __ _(_)_ __ |  _ \ ___  ___ ___  _ __",
    r"| | | |/ _ \| '_ ` _ \ / _` | | '_ \| |_) / _ \/ __/ _ \| '_ \ ",
    r"| |_| | (_) | | | | | | (_| | | | | |  _ <  __/ (_| (_) | | | |",
    r"|____/ \___/|_| |_| |_|\__,_|_|_| |_|_| \_\___|\___\___/|_| |_|",
)


def sanitize(value: Any) -> str:
    """Remove control characters (including ESC) so untrusted text cannot drive the terminal."""
    return _CONTROL.sub("", str(value)).replace("\r", "")


def visible_length(text: str) -> int:
    return len(_ANSI.sub("", text))


def enable_ansi() -> bool:
    """Enable ANSI escape processing on Windows consoles; True when colour can be used."""
    if os.name != "nt":
        return True
    try:
        import colorama  # declared project requirement; optional at runtime

        fix = getattr(colorama, "just_fix_windows_console", None)
        if fix:
            fix()
        else:  # colorama < 0.4.6
            colorama.init()
        return True
    except Exception:  # noqa: BLE001 - any failure simply disables colour
        pass
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) and kernel32.SetConsoleMode(handle, mode.value | 0x0004):
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


def detect_capabilities(*, injected_output: bool, stream: Any = None, environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Decide layout/colour/unicode/width from the output stream and environment."""
    env = os.environ if environ is None else environ
    stream = stream if stream is not None else sys.stdout
    mode = env.get("DOMAINRECON_UI", "").strip().lower()
    is_tty = bool(getattr(stream, "isatty", lambda: False)())
    layout = not injected_output and mode != "plain" and (is_tty or mode in {"styled", "ascii"})
    color = layout and "NO_COLOR" not in env and env.get("TERM", "") != "dumb" and (is_tty or mode == "styled") and enable_ansi()
    encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
    unicode_ok = layout and mode != "ascii" and encoding in {"utf8", "utf8sig"}
    try:
        width = int(env.get("DOMAINRECON_UI_WIDTH") or shutil.get_terminal_size((100, 30)).columns)
    except ValueError:
        width = 100
    return {"layout": layout, "color": color, "unicode": unicode_ok, "width": max(60, min(width, 140))}


class Console:
    def __init__(self, write: Callable[[str], object], *, layout: bool = False, color: bool = False, unicode: bool = False, width: int = 100, stream: Any = None) -> None:
        self._write = write
        self.layout, self.color, self.unicode, self.width = layout, color and layout, unicode and layout, max(60, width)
        self._stream = stream if stream is not None else sys.stdout
        self._spinner: tuple[threading.Event, threading.Thread, str, float] | None = None
        self.symbols = {"ok": "✔", "fail": "✖", "warn": "!", "info": "•", "on": "●", "off": "○", "h": "─", "v": "│", "arrow": "›"} if self.unicode else \
                       {"ok": "+", "fail": "x", "warn": "!", "info": "*", "on": "*", "off": "o", "h": "-", "v": "|", "arrow": ">"}

    # ------------------------------------------------------------------ primitives
    def style(self, text: str, *names: str) -> str:
        if not self.color or not names:
            return text
        return f"\x1b[{';'.join(CODES[name] for name in names)}m{text}\x1b[0m"

    def write(self, line: str = "") -> None:
        self.stop_task()
        self._write(line)

    def wrapped(self, text: str, *, first: str = "", rest: str = "  ") -> None:
        """Write text wrapped to the terminal width (layout mode); never truncates a message."""
        room = max(20, self.width - len(first))
        parts = textwrap.wrap(text, room, subsequent_indent=rest, break_long_words=True, break_on_hyphens=False) or [""]
        for index, part in enumerate(parts):
            self.write((first if index == 0 else " " * len(first)) + part)

    def pad(self, text: str, width: int) -> str:
        return text + " " * max(0, width - visible_length(text))

    def truncate(self, text: str, width: int) -> str:
        if len(text) <= width:
            return text
        ellipsis = "…" if self.unicode else "..."
        return text[: max(0, width - len(ellipsis))] + ellipsis if width > len(ellipsis) else text[:width]

    def badge(self, text: str, styles: tuple[str, ...]) -> str:
        return self.style(text, *styles)

    def severity(self, value: Any) -> str:
        level = str(value.get("level") if isinstance(value, dict) else value or "").upper()
        return self.badge(level or "-", SEVERITY_STYLE.get(level, ("grey",)))

    # ------------------------------------------------------------------ messages
    def emit(self, line: Any) -> None:
        """Write one application message; in layout mode classify it and add a status marker."""
        text = sanitize(line)
        if not self.layout:
            self.write(text)
            return
        while text.startswith("\n"):
            self.write("")
            text = text[1:]
        if "\n" in text:
            for part in text.split("\n"):
                self.write("  " + part)
            return
        stripped = text.strip()
        if not stripped:
            self.write("")
        elif re.match(r"^\[\d+\]", stripped):
            number, _, rest = stripped.partition("]")
            parts = textwrap.wrap(rest.strip(), max(20, self.width - len(number) - 4), break_on_hyphens=False) or [""]
            self.write(f"  {self.style(number + ']', 'bold', 'cyan')} {parts[0]}")
            for part in parts[1:]:
                self.write(" " * (len(number) + 4) + part)
        elif stripped[:14].replace(" ", "").replace("-", "").replace("&", "").isalnum() and stripped.split("(")[0].isupper() and len(stripped) < 90:
            self.heading(stripped)
        elif text.startswith("  "):
            self.write(self.style(text, "grey") if self.color else text)
        elif _ERROR.search(stripped):
            self.error(stripped)
        elif _WARN.search(stripped):
            self.warn(stripped)
        elif _SUCCESS.search(stripped):
            self.success(stripped)
        else:
            self.wrapped(text)

    def _marked(self, symbol: str, styles: tuple[str, ...], text: str, text_styles: tuple[str, ...] = ()) -> None:
        if not self.layout:
            self.write(sanitize(text))
            return
        parts = textwrap.wrap(sanitize(text), max(20, self.width - 2), break_on_hyphens=False) or [""]
        for index, part in enumerate(parts):
            self.write(f"{self.style(symbol, *styles) if index == 0 else ' '} {self.style(part, *text_styles)}")

    def success(self, text: str) -> None:
        self._marked(self.symbols["ok"], ("green",), text)

    def warn(self, text: str) -> None:
        self._marked(self.symbols["warn"], ("bold", "yellow"), text)

    def error(self, text: str) -> None:
        self._marked(self.symbols["fail"], ("bold", "red"), text, ("red",))

    def info(self, text: str) -> None:
        self._marked(self.symbols["info"], ("cyan",), text)

    def prompt(self, text: str) -> str:
        if not self.layout:
            return text
        return f"{self.style(self.symbols['arrow'], 'bold', 'cyan')} {self.style(text, 'bold')}"

    # ------------------------------------------------------------------ structure
    def rule(self, title: str = "") -> None:
        if not self.layout:
            self.write("-" * 68 if not title else f"--- {title} ---")
            return
        line = self.symbols["h"] * self.width
        if title:
            label = f" {title} "
            line = self.symbols["h"] * 2 + self.style(label, "bold", "cyan") + self.symbols["h"] * max(0, self.width - 2 - len(label))
        self.write(line if title else self.style(line, "grey"))

    def heading(self, title: str) -> None:
        if not self.layout:
            self.write(title)
            return
        self.rule(sanitize(title))

    def banner(self, version: str, tagline: str) -> None:
        if not self.layout:
            return
        self.write("")
        if self.width >= 68:
            for row in BANNER:
                self.write(self.style(row, "bold", "cyan"))
            self.write(f"{self.style('  V2', 'bold', 'white')}  {self.style('v' + version, 'cyan')}  {self.style(self.symbols['v'], 'grey')}  {tagline}")
        else:
            self.write(f"{self.style('DOMAINRECON V2', 'bold', 'cyan')} v{version}")
            self.write(tagline)

    def key_values(self, title: str, rows: Iterable[tuple[str, Any, str | None]]) -> None:
        """Aligned label/value block; ``state`` (OK/WARN/FAIL/INFO) colours the value."""
        rows = [(sanitize(label), sanitize(value), state) for label, value, state in rows]
        if not self.layout:
            for label, value, _state in rows:
                self.write(f"{label}: {value}")
            return
        self.rule(title)
        label_width = max((len(label) for label, _v, _s in rows), default=0)
        two_columns = self.width >= 110 and len(rows) > 6
        cells = []
        for label, value, state in rows:
            room = (self.width // 2 if two_columns else self.width) - label_width - 5
            shown = self.truncate(value, max(12, room))
            cells.append(f" {self.style(self.pad(label, label_width), 'grey')}  {self.style(shown, *STATE_STYLE.get(state or '', ()))}")
        if two_columns:
            half = (len(cells) + 1) // 2
            for index in range(half):
                right = cells[index + half] if index + half < len(cells) else ""
                self.write(self.pad(cells[index], self.width // 2) + right)
        else:
            for label, value, state in rows:
                room = max(12, self.width - label_width - 4)
                parts = textwrap.wrap(value, room, break_on_hyphens=False) or [""]
                for index, part in enumerate(parts):
                    self.write(f" {self.style(self.pad(label if index == 0 else '', label_width), 'grey')}  {self.style(part, *STATE_STYLE.get(state or '', ()))}")

    def panel(self, title: str, lines: Iterable[str], kind: str = "INFO") -> None:
        """Bordered notice block (used for authorization pre-flight and summaries)."""
        lines = [sanitize(line) for line in lines]
        if not self.layout:
            self.write(f"--- {title} ---")
            for line in lines:
                self.write(line)
            return
        colour = STATE_STYLE.get(kind, ("cyan",))
        bar = self.style(self.symbols["v"], *colour)
        self.write(self.style(self.symbols["h"] * 2 + f" {title} " + self.symbols["h"] * max(0, self.width - len(title) - 4), "bold", *colour))
        for line in lines:
            for index, part in enumerate(textwrap.wrap(line, self.width - 2, subsequent_indent=" " * 12, break_on_hyphens=False) or [""]):
                self.write(f"{bar} {part}")
        self.write(self.style(self.symbols["h"] * self.width, *colour))

    def table(self, columns: list[dict[str, Any]], rows: list[dict[str, Any]], *, title: str | None = None, max_rows: int = 25, empty: str = "No entries.") -> None:
        """Width-aware table. Column keys: key, title, flex (shrinks/truncates), kind (severity|state|kind), min."""
        if title:
            self.heading(title) if self.layout else self.write(title)
        if not rows:
            self.write(f"  {empty}")
            return
        shown = rows[:max_rows]
        text = [[sanitize("" if row.get(col["key"]) is None else row.get(col["key"])) for col in columns] for row in shown]
        widths = [max(len(col["title"]), *(len(line[index]) for line in text)) for index, col in enumerate(columns)]
        separator = f" {self.symbols['v']} " if self.layout else " | "
        budget = self.width - len(separator) * (len(columns) - 1) - 1
        while sum(widths) > budget:
            flexible = [i for i, col in enumerate(columns) if col.get("flex") and widths[i] > col.get("min", 10)]
            if not flexible:
                widest = max(range(len(widths)), key=lambda i: widths[i])
                if widths[widest] <= 6:
                    break
                widths[widest] -= 1
                continue
            widths[max(flexible, key=lambda i: widths[i])] -= 1
        header = separator.join(self.pad(self.style(col["title"], "bold") if self.layout else col["title"], widths[i]) for i, col in enumerate(columns))
        self.write(" " + header)
        self.write(" " + ("-+-" if not self.layout else self.symbols["h"] + ("┼" if self.unicode else "+") + self.symbols["h"]).join(self.symbols["h"] * w if self.layout else "-" * w for w in widths))
        for line in text:
            cells = []
            for index, col in enumerate(columns):
                value = self.truncate(line[index], widths[index])
                kind = col.get("kind")
                if self.layout and kind == "severity":
                    value = self.badge(value, SEVERITY_STYLE.get(value.upper(), ("grey",)))
                elif self.layout and kind == "state":
                    value = self.badge(value, STATE_STYLE.get(value.upper().split()[0] if value else "", ()))
                elif self.layout and kind == "kind":
                    value = self.badge(value, KIND_STYLE.get(value.upper(), ()))
                cells.append(self.pad(value, widths[index]))
            self.write(" " + separator.join(cells).rstrip())
        if len(rows) > max_rows:
            self.write(self.style(f"  ... {len(rows) - max_rows} more row(s) in the saved artifact", "grey"))

    def menu(self, groups: list[tuple[str, list[dict[str, str]]]]) -> None:
        """Grouped navigation. Plain mode keeps the legacy ``[N] Label - note`` line format."""
        if not self.layout:
            for title, entries in groups:
                self.write(title)
                for entry in entries:
                    self.write(f"[{entry['number']}] {entry['label']}" + (f" - {entry['note']}" if entry.get("note") else ""))
            return
        shown = lambda e: e.get("short") or e["label"]  # noqa: E731 - compact labels leave room for prerequisite hints
        label_width = min(max(len(shown(e)) for _t, entries in groups for e in entries), max(34, self.width // 2 - 12))
        for title, entries in groups:
            self.write("")
            self.rule(title)
            for entry in entries:
                number = self.style(f"[{entry['number']:>2}]", "bold", "cyan")
                if entry["number"] == "0":
                    self.write(f" {number} {shown(entry)}")
                    continue
                state, hint = menu_state(entry.get("note", ""))
                dot = self.style(self.symbols["on"] if state == "READY" else self.symbols["off"], *STATE_STYLE[state])
                kind = self.pad(self.badge(entry.get("kind", ""), KIND_STYLE.get(entry.get("kind", ""), ())), 8)
                line = f" {number} {self.pad(self.truncate(shown(entry), label_width), label_width)}  {kind} {dot} {self.style(self.pad(state, 7), *STATE_STYLE[state])}"
                room = self.width - visible_length(line) - 1
                if hint and room >= 16:
                    line += " " + self.style(self.truncate(hint, room), "grey")
                self.write(line)
                if hint and room < 16:
                    self.write(" " * 7 + self.style(self.truncate(hint, self.width - 8), "grey"))

    # ------------------------------------------------------------------ progress
    def start_task(self, message: str) -> None:
        """Show activity for a blocking step. Any later output (or stop_task) ends the indicator."""
        self.stop_task()
        message = sanitize(message)
        if not self.layout or not getattr(self._stream, "isatty", lambda: False)():
            self._write(f"{message} ..." if not self.layout else f"{self.style(self.symbols['info'], 'cyan')} {message} ...")
            self._spinner = (threading.Event(), threading.Thread(), message, time.monotonic())
            return
        stop = threading.Event()
        started = time.monotonic()
        frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if self.unicode else "|/-\\"

        def spin() -> None:
            index = 0
            while not stop.wait(0.12):
                frame = self.style(frames[index % len(frames)], "cyan")
                self._stream.write(f"\r{frame} {message} ({int(time.monotonic() - started)}s) ")
                self._stream.flush()
                index += 1

        thread = threading.Thread(target=spin, daemon=True)
        self._spinner = (stop, thread, message, started)
        thread.start()

    def stop_task(self, outcome: str | None = None) -> None:
        if self._spinner is None:
            return
        stop, thread, message, started = self._spinner
        self._spinner = None
        stop.set()
        if thread.is_alive():
            thread.join(timeout=1)
            self._stream.write("\r" + " " * min(self.width, len(message) + 16) + "\r")
            self._stream.flush()
        if outcome:
            elapsed = f"{time.monotonic() - started:.1f}s"
            self._write(f"{message}: {outcome} ({elapsed})" if not self.layout else f"{self.style(self.symbols['ok'], 'green')} {message}: {outcome} ({elapsed})")


def menu_state(note: str) -> tuple[str, str]:
    """Map a legacy availability note to (READY|NEEDS|BLOCKED, hint)."""
    text = (note or "").strip()
    lowered = text.lower()
    if not text or lowered == "available":
        return "READY", ""
    if lowered.startswith("available"):
        return "READY", text[len("available"):].lstrip(" ;:,-")
    hint = re.sub(r"(?i)^(unavailable|needs|requires)[:\s]*", "", text)
    if any(word in lowered for word in ("missing", "not installed", "disabled by engagement")):
        return "BLOCKED", hint
    return "NEEDS", hint
