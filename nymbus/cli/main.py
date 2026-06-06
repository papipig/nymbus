from __future__ import annotations

import sys
import uuid
from typing import Optional

import typer
from rich.console import Console

from ..config import Settings, get_settings
from ..session.context import Session, SessionLockedError
from .transparency import TransparencyLog
from .shell import ShellRunner

app = typer.Typer(
    name="nb",
    help="nymbus — anonymising AI proxy",
    no_args_is_help=True,
    add_completion=True,
)
session_app = typer.Typer(help="Manage nymbus sessions.")
app.add_typer(session_app, name="session")

console = Console()
err_console = Console(stderr=True)


# ── Global options ─────────────────────────────────────────────────────────────

class _State:
    verbose: bool = False
    quiet: bool = False
    debug: bool = False
    log_file: str | None = None
    allow_semantic_warn: bool = False
    model: str | None = None
    session_id: str | None = None


state = _State()


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    prompt: Optional[str] = typer.Argument(None, help="Prompt text (or omit to read stdin)."),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose transparency log."),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Suppress transparency output."),
    debug: bool = typer.Option(False, "-d", "--debug", help="Debug mode (print anonymised prompt)."),
    log_file: Optional[str] = typer.Option(None, "--log-file", help="Append transparency log to file."),
    allow_semantic_warn: bool = typer.Option(
        False, "--allow-semantic-warn", help="Treat semantic-check warnings as non-fatal."
    ),
    model: Optional[str] = typer.Option(None, "--model", help="Override external LLM model."),
    session: Optional[str] = typer.Option(
        None,
        "--session",
        envvar="NB_SESSION",
        help="Session ID (creates new session if not found).",
    ),
) -> None:
    """Send a prompt through the nymbus anonymisation proxy."""
    # Sub-command path — do nothing here
    if ctx.invoked_subcommand is not None:
        return

    state.verbose = verbose
    state.quiet = quiet
    state.debug = debug
    state.log_file = log_file
    state.allow_semantic_warn = allow_semantic_warn
    state.model = model

    # Resolve prompt
    if prompt is None:
        if sys.stdin.isatty():
            err_console.print("[yellow]No prompt provided and no stdin pipe detected.[/]")
            raise typer.Exit(1)
        prompt = sys.stdin.read().strip()

    if not prompt:
        err_console.print("[red]Empty prompt.[/]")
        raise typer.Exit(1)

    # Capture-and-inject: nb "explain" -- nmap …
    import os
    capture_cmd = os.environ.pop("_NB_CAPTURE_SHELL", "")
    if capture_cmd:
        settings_pre = _load_settings(model_override=model)
        runner_pre = ShellRunner(
            confirm=settings_pre.shell_confirm,
            allow_patterns=settings_pre.shell_allow,
            deny_patterns=settings_pre.shell_deny,
        )
        captured = runner_pre.capture(capture_cmd)
        if captured is not None:
            prompt = f"$ {capture_cmd}\n{captured.rstrip()}\n\n{prompt}"
        else:
            # User denied — proceed with original prompt only
            pass

    # Session
    session_id = session or str(uuid.uuid4())
    state.session_id = session_id

    settings = _load_settings(model_override=model)

    sess = Session(session_id, settings)
    try:
        sess.load()
    except SessionLockedError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)

    log = TransparencyLog()
    try:
        real_reply, log = sess.send(
            prompt,
            allow_semantic_warn=allow_semantic_warn,
            log=log,
            debug=debug,
        )
    except Exception as exc:
        err_console.print(f"[red]Error:[/] {exc}")
        if debug:
            import traceback
            traceback.print_exc()
        raise typer.Exit(1)
    finally:
        sess.close()

    # Print reply
    console.print(real_reply)

    # Transparency output
    if not quiet:
        if verbose:
            log.render_verbose(console)
        else:
            log.render_compact(console)

    # Log to file
    if log_file:
        _append_log_file(log_file, session_id, prompt, real_reply, log, verbose)


# ── Session sub-commands ───────────────────────────────────────────────────────

@session_app.command("new")
def session_new(
    name: Optional[str] = typer.Argument(None, help="Human-readable session name (used as ID).")
) -> None:
    """Start a new named (or random) session."""
    sid = name or str(uuid.uuid4())
    settings = _load_settings()
    sess = Session(sid, settings)
    sess.load()
    sess.close()
    console.print(f"Session [bold]{sid}[/] created.")
    console.print(f"Use [cyan]--session {sid}[/] (or set NB_SESSION={sid}) to resume.")


@session_app.command("list")
def session_list() -> None:
    """List all saved sessions."""
    import datetime

    sessions = Session.list_sessions()
    if not sessions:
        console.print("[dim]No sessions found.[/]")
        return
    for s in sessions:
        mtime = datetime.datetime.fromtimestamp(s["mtime"]).strftime("%Y-%m-%d %H:%M")
        console.print(f"  [cyan]{s['id']}[/]  {mtime}  ({s['size']} bytes)")


@session_app.command("export")
def session_export(
    session_id: str = typer.Argument(..., help="Session ID to export."),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Output file (default: stdout)."),
) -> None:
    """Export a session transcript with real values restored."""
    settings = _load_settings()
    sess = Session(session_id, settings)
    try:
        sess.load()
    except SessionLockedError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(1)

    transcript = sess.export_transcript()
    sess.close()

    if output:
        from pathlib import Path
        Path(output).write_text(transcript)
        console.print(f"Transcript written to [cyan]{output}[/]")
    else:
        console.print(transcript)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_settings(model_override: str | None = None) -> Settings:
    settings = get_settings()
    if model_override:
        settings = settings.model_copy(update={"external_llm_model": model_override})
    return settings


def _append_log_file(
    path: str,
    session_id: str,
    prompt: str,
    reply: str,
    log: TransparencyLog,
    verbose: bool,
) -> None:
    from pathlib import Path
    import datetime

    lines = [
        f"\n=== {datetime.datetime.now().isoformat()} session={session_id} ===",
        f"PROMPT: {prompt[:200]}{'…' if len(prompt) > 200 else ''}",
        f"REPLY:  {reply[:200]}{'…' if len(reply) > 200 else ''}",
    ]
    if verbose:
        for ev in log.events:
            if ev.kind == "SUBST":
                lines.append(f"  [SUBST] {ev.real!r} → {ev.fake!r}  ({ev.nb_type})")
            elif ev.kind == "PASS":
                lines.append(f"  [PASS]  {ev.real!r}  ({ev.nb_type})")
            elif ev.message:
                lines.append(f"  [{ev.kind}] {ev.message}")
    else:
        lines.append(
            f"  {log.n_subst} substitution(s) · {log.n_pass} pass"
        )

    Path(path).open("a").write("\n".join(lines) + "\n")


# ── Entry-point split at '--' for inline shell commands ──────────────────────

def _preprocess_argv() -> None:
    """
    Allow:  nb [nb-flags] [prompt] -- shell command

    When a prompt is present alongside the shell command the output is captured
    and prepended to the prompt (capture-and-inject mode).  When there is no
    prompt the command is run immediately with no LLM call (execute-only mode).
    """
    if "--" not in sys.argv:
        return
    idx = sys.argv.index("--")
    nb_args = sys.argv[1:idx]
    shell_cmd = " ".join(sys.argv[idx + 1:])
    sys.argv[1:] = nb_args
    if not shell_cmd:
        return
    import os
    # Detect whether there is a prompt argument among the remaining nb_args
    has_prompt = any(a for a in nb_args if not a.startswith("-"))
    if has_prompt:
        os.environ["_NB_CAPTURE_SHELL"] = shell_cmd
    else:
        os.environ["_NB_INLINE_SHELL"] = shell_cmd


def run() -> None:
    import os
    _preprocess_argv()

    # Execute-only mode: no prompt, just run the shell command
    inline = os.environ.pop("_NB_INLINE_SHELL", "")
    if inline:
        settings = _load_settings()
        runner = ShellRunner(
            confirm=settings.shell_confirm,
            allow_patterns=settings.shell_allow,
            deny_patterns=settings.shell_deny,
        )
        raise SystemExit(runner.run(inline) or 0)

    app()
