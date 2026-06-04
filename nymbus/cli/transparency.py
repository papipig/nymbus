from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from rich.console import Console
from rich.panel import Panel
from rich.text import Text


EventKind = Literal["SUBST", "PASS", "WARN", "OK", "BLOCK"]

_KIND_COLOR: dict[str, str] = {
    "SUBST": "cyan",
    "PASS":  "dim",
    "WARN":  "yellow",
    "OK":    "green",
    "BLOCK": "red",
}


@dataclass
class Event:
    kind: EventKind
    real: str = ""
    fake: str | None = None
    nb_type: str = ""
    message: str = ""


@dataclass
class TransparencyLog:
    events: list[Event] = field(default_factory=list)

    def add(self, event: Event) -> None:
        self.events.append(event)

    # ── Convenience adders ────────────────────────────────────────────────────

    def subst(self, real: str, fake: str, nb_type: str) -> None:
        self.add(Event("SUBST", real=real, fake=fake, nb_type=nb_type))

    def passthrough(self, real: str, nb_type: str, message: str = "") -> None:
        self.add(Event("PASS", real=real, nb_type=nb_type, message=message))

    def warn(self, message: str) -> None:
        self.add(Event("WARN", message=message))

    def ok(self, message: str) -> None:
        self.add(Event("OK", message=message))

    def block(self, message: str) -> None:
        self.add(Event("BLOCK", message=message))

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def n_subst(self) -> int:
        return sum(1 for e in self.events if e.kind == "SUBST")

    @property
    def n_pass(self) -> int:
        return sum(1 for e in self.events if e.kind == "PASS")

    @property
    def has_warn(self) -> bool:
        return any(e.kind == "WARN" for e in self.events)

    @property
    def has_block(self) -> bool:
        return any(e.kind == "BLOCK" for e in self.events)

    # ── Rendering ─────────────────────────────────────────────────────────────

    def render_compact(self, console: Console | None = None) -> str:
        """Return a one-line summary and optionally print it."""
        subst_part = (
            f"[cyan]{self.n_subst} substitution{'s' if self.n_subst != 1 else ''}[/]"
        )
        pass_part = (
            f"[dim]{self.n_pass} pass[/]" if self.n_pass else ""
        )
        if self.has_block:
            watchdog = "[red]watchdog ✗[/]"
        elif self.has_warn:
            watchdog = "[yellow]watchdog ⚠[/]"
        else:
            watchdog = "[green]watchdog ✓[/]"

        parts = [p for p in [subst_part, pass_part, watchdog] if p]
        line = " · ".join(parts)
        if console:
            console.print(line)
        return line

    def render_verbose(self, console: Console) -> None:
        """Print a rich panel with all events."""
        text = Text()
        for ev in self.events:
            color = _KIND_COLOR.get(ev.kind, "white")
            tag = f"[{ev.kind}]"
            if ev.kind == "SUBST":
                text.append(f"{tag} ", style=color)
                text.append(ev.real or "", style="bold")
                text.append(" → ", style=color)
                text.append(ev.fake or "", style="bold green")
                text.append(f"  ({ev.nb_type})\n", style="dim")
            elif ev.kind == "PASS":
                detail = ev.message or "unchanged"
                text.append(f"{tag} ", style=color)
                text.append(ev.real, style="bold")
                text.append(f"  {detail}\n", style="dim")
            else:
                msg = ev.message or f"{ev.nb_type}"
                text.append(f"{tag} {msg}\n", style=color)

        console.print(
            Panel(text, title="[bold]Transparency Log[/]", border_style="blue")
        )
