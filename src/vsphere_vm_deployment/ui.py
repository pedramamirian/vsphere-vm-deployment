"""Terminal user interface: the live step-by-step deployment view and the interactive prompts.

Design:
* The step list, the active transfer bar and the weighted overall bar are drawn by one `rich.live.Live`
  display that always sits at the bottom of the terminal.
* When a step needs input (login, certificate trust, EULA, placement, sizing...) the live display is
  paused, a short header names the step, the questions are asked, and each answer is echoed as a
  one-line record. The live display then resumes underneath, so the scrollback reads as a log of every
  decision that was made.
* In non-interactive mode (`--yes`) every prompt either takes its default (if the caller marks the
  default as safe to assume) or raises MissingInput naming the manifest field that should be set.
"""

from __future__ import annotations

import contextlib
import fnmatch
import inspect
import logging
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

import questionary
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    ProgressColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from .errors import MissingInput, UserAborted
from .logsetup import FILE_ONLY, safe_url
from .units import human_size, size_unit

log = logging.getLogger(__name__)

# All UI goes to stderr so `--json` output on stdout stays machine-readable.
# emoji=False: Rich would turn ":AB:" in a colon-separated certificate fingerprint into an emoji, so about 1 in 9
# fingerprints was shown mangled at the very prompt that asks the user to compare it.
console = Console(stderr=True, highlight=False, emoji=False)
# Newer questionary releases show a description under the highlighted choice; older ones get titles only.
_CHOICE_DESCRIPTIONS = "description" in inspect.signature(questionary.Choice.__init__).parameters

_ICONS = {
    "pending": Text("○", style="dim"),
    "done": Text("✔", style="green"),
    "skipped": Text("–", style="dim"),
    "failed": Text("✖", style="bold red"),
    "warn": Text("!", style="yellow"),
}


@dataclass
class Step:
    key: str
    title: str
    weight: float = 1.0
    status: str = "pending"  # pending | running | done | skipped | failed | warn
    detail: str = ""
    fraction: float = 0.0  # 0..1 progress within the step, used for the weighted overall bar
    notes: list[tuple[str, str]] = field(default_factory=list)  # (style, text)
    timed: bool = True  # False for steps that are mostly the user's own answers (their time is not shown)
    t0: float | None = None  # monotonic start
    w0: float = 0.0  # time spent waiting for the user before this step started
    elapsed: float | None = None  # working time, excluding time spent waiting for the user's answers


class SizeColumn(ProgressColumn):
    """'0.9/3.2 GB' (both in the total's unit), or the bytes so far when the total is unknown. Rich's own column is
    1000-based ('3.4 GB'), so the same file showed two different sizes in one run."""

    def render(self, task) -> Text:
        if task.total is None:
            return Text(human_size(task.completed), style="progress.download")
        i = size_unit(task.total)
        done = human_size(task.completed, i).rsplit(" ", 1)[0]
        return Text(f"{done}/{human_size(task.total, i)}", style="progress.download")


class SpeedColumn(ProgressColumn):
    """'56.1 MB/s', in the same units as SizeColumn."""

    def render(self, task) -> Text:
        speed = task.finished_speed or task.speed
        return Text("?" if speed is None else f"{human_size(speed)}/s", style="progress.data.speed")


def duration(seconds: float) -> str:
    """'<1s', '12s', '3m 05s', '1h 02m'."""
    s = int(round(seconds))
    if seconds < 1:
        return "<1s"
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    return f"{s // 3600}h {s % 3600 // 60:02d}m"


class DeploymentView:
    """Live step view with a per-transfer progress bar and a weighted overall progress bar."""

    def __init__(self, title: str, steps: Sequence[tuple[str, str, float]], enabled: bool = True,
                 untimed: Sequence[str] = ()):
        self.title = title
        self.steps: dict[str, Step] = {k: Step(k, t, w, timed=k not in untimed) for k, t, w in steps}
        # Time spent waiting for the user's answers is left out of every step's time.
        self._wait_depth = 0
        self._wait_since = 0.0
        self._waited = 0.0
        self.enabled = enabled and console.is_terminal
        self._live: Live | None = None
        self._pause_depth = 0  # paused() nesting
        self._spinner = Spinner("dots", style="cyan")
        self._transfer = Progress(
            TextColumn("   [cyan]{task.description}"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            SizeColumn(),
            SpeedColumn(),
            TimeRemainingColumn(),
            console=console,
            auto_refresh=False,
            expand=True,
        )
        self._transfer_task: TaskID | None = None
        self._transfer_step: str | None = None
        self._overall = Progress(
            TextColumn("[bold]Overall"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            console=console,
            auto_refresh=False,
            expand=True,
        )
        self._overall_task = self._overall.add_task("overall", total=100)

    # ----------------------------------------------------------------- lifecycle
    def _new_live(self) -> Live:
        return Live(get_renderable=self._render, console=console, refresh_per_second=8,
                    transient=True, redirect_stderr=False, redirect_stdout=False)

    def __enter__(self) -> DeploymentView:
        if self.enabled:
            self._live = self._new_live()
            self._live.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._live:
            self._live.stop()
            self._live = None
        # Leave a permanent copy of the final state in the scrollback.
        console.print(self._render(final=True))

    @contextlib.contextmanager
    def paused(self, header: str | None = None) -> Iterator[None]:
        """Temporarily remove the live display so prompts can be shown. Nestable: a section opened inside another
        (e.g. the key-provider fix inside "Virtual hardware") must not restart the display while the outer one is
        still asking questions, or the prompts are drawn over by the refreshing panel."""
        live = self._live
        if live and self._pause_depth == 0:
            live.stop()
        self._pause_depth += 1
        if header:
            console.print(Text(f"── {header} ", style="bold cyan") + Text("─" * 20, style="cyan"))
        try:
            yield
        finally:
            self._pause_depth -= 1
            if live and self._pause_depth == 0 and self._live is live:
                # A new Live, not live.start(): a restarted Live still remembers the height it had before it was
                # stopped and moves the cursor up that far on its first refresh, erasing the last lines printed
                # while it was paused (the review screen lost all but its first lines).
                self._live = self._new_live()
                self._live.start()

    @contextlib.contextmanager
    def waiting(self) -> Iterator[None]:
        """Around a question: this time is the user's, not the tool's, so steps do not count it."""
        if self._wait_depth == 0:
            self._wait_since = time.monotonic()
        self._wait_depth += 1
        try:
            yield
        finally:
            self._wait_depth -= 1
            if self._wait_depth == 0:
                self._waited += time.monotonic() - self._wait_since

    def _waited_now(self) -> float:
        return self._waited + (time.monotonic() - self._wait_since if self._wait_depth else 0.0)

    def _working(self, s: Step) -> float:
        return max(0.0, (time.monotonic() - s.t0) - (self._waited_now() - s.w0)) if s.t0 is not None else 0.0

    def timings(self) -> dict[str, float]:
        """Working seconds per finished, timed step (for --json)."""
        return {k: round(s.elapsed, 1) for k, s in self.steps.items() if s.timed and s.elapsed is not None}

    # ----------------------------------------------------------------- step state
    def start(self, key: str, detail: str = "") -> None:
        """Start a step. One that is running already goes on to its next phase (e.g. the full check of an ISO copy,
        then copying it): its time keeps counting, so the time shown covers every phase."""
        s = self.steps[key]
        if s.status != "running":
            s.t0, s.w0 = time.monotonic(), self._waited_now()
        s.status, s.detail, s.fraction, s.elapsed = "running", detail, 0.0, None
        self._log_plain(f"... {s.title}" + (f": {detail}" if detail else ""))
        self._refresh()

    def update(self, key: str, detail: str | None = None, fraction: float | None = None) -> None:
        s = self.steps[key]
        if detail is not None:
            s.detail = detail
        if fraction is not None:
            s.fraction = max(0.0, min(1.0, fraction))
        self._refresh()

    def done(self, key: str, detail: str | None = None, status: str = "done") -> None:
        s = self.steps[key]
        s.status, s.fraction = status, 1.0
        if detail is not None:
            s.detail = detail
        s.elapsed = self._working(s) if (s.t0 is not None and status != "skipped") else None
        if self._transfer_step == key:
            self.end_transfer()
        took = f" ({duration(s.elapsed)})" if s.timed and s.elapsed is not None else ""
        line = f"[{status}] {s.title}" + (f": {s.detail}" if s.detail else "") + took
        log.info("%s", line, extra=FILE_ONLY)  # the log file shows what was done, as the screen did
        self._log_plain(line)
        self._refresh()

    def skip(self, key: str, detail: str = "") -> None:
        self.done(key, detail, status="skipped")

    def reset(self, *keys: str) -> None:
        """Back to 'pending' (used when the user goes back to change answers)."""
        for key in keys:
            s = self.steps[key]
            s.status, s.detail, s.fraction = "pending", "", 0.0
            s.t0, s.elapsed = None, None
            s.notes.clear()
        self._refresh()

    def fail(self, key: str, detail: str = "") -> None:
        self.done(key, detail, status="failed")

    def note(self, key: str, text: str, style: str = "yellow") -> None:
        """Attach a warning or info line under a step (e.g. 'datastore would be 92% full')."""
        self.steps[key].notes.append((style, text))
        words = style.split()  # a blocker (red) or a warning (yellow) keeps its weight in the log
        level = logging.ERROR if "red" in words else logging.WARNING if "yellow" in words else logging.INFO
        log.log(level, "    note: %s", text, extra=FILE_ONLY)
        self._log_plain(f"    note: {text}")
        self._refresh()

    def fail_running(self, detail: str = "") -> None:
        for s in self.steps.values():
            if s.status == "running":
                self.fail(s.key, detail or s.detail)

    # ----------------------------------------------------------------- transfers
    def begin_transfer(self, key: str, description: str, total: int | None) -> Callable[[int], None]:
        """Start a byte-level progress bar under `key`; returns a callback taking bytes just moved."""
        self.end_transfer()
        self._transfer_step = key
        # Descriptions name files, e.g. "Checking [datastore1] iso/x.iso": text, never Rich markup.
        self._transfer_task = self._transfer.add_task(escape(description), total=total)
        moved = 0
        last_log = [0.0]

        def advance(nbytes: int) -> None:
            nonlocal moved
            moved += nbytes
            assert self._transfer_task is not None
            self._transfer.update(self._transfer_task, completed=moved)
            if total:
                self.steps[key].fraction = min(1.0, moved / total)
            now = time.monotonic()
            if not self.enabled and now - last_log[0] > 5:  # plain-mode heartbeat
                last_log[0] = now
                pct = f"{moved * 100 / total:.0f}%" if total else human_size(moved)
                console.print(f"    {escape(description)}: {pct}")
            self._refresh()

        return advance

    def end_transfer(self) -> None:
        if self._transfer_task is not None:
            self._transfer.remove_task(self._transfer_task)
        self._transfer_task = None
        self._transfer_step = None

    # ----------------------------------------------------------------- rendering
    def overall_fraction(self) -> float:
        total = sum(s.weight for s in self.steps.values())
        if not total:
            return 0.0
        acc = 0.0
        for s in self.steps.values():
            if s.status in ("done", "skipped", "warn"):
                acc += s.weight
            elif s.status in ("running", "failed"):
                acc += s.weight * s.fraction
        return acc / total

    def _refresh(self) -> None:
        self._overall.update(self._overall_task, completed=round(self.overall_fraction() * 100, 1))
        if self._live:
            self._live.refresh()

    def _log_plain(self, text: str) -> None:
        if not self.enabled:
            console.print(text, markup=False)

    def _render(self, final: bool = False):
        grid = Table.grid(padding=(0, 1), expand=True)
        grid.add_column(width=2)
        grid.add_column(ratio=1)
        grid.add_column(justify="right", no_wrap=True)  # time spent (working time only)
        total = 0.0
        for s in self.steps.values():
            icon: Any = self._spinner if (s.status == "running" and not final) else _ICONS.get(s.status, _ICONS["pending"])
            label = Text(s.title, style="bold" if s.status == "running" else ("dim" if s.status == "pending" else ""))
            if s.detail:
                label.append(f"  {s.detail}", style="dim")
            took = ""
            if s.timed and s.elapsed is not None:
                took = duration(s.elapsed)
                total += s.elapsed
            elif s.timed and s.status == "running" and s.t0 is not None and not final:
                took = duration(self._working(s))
            grid.add_row(icon, label, Text(took, style="dim"))
            for style, note in s.notes:
                grid.add_row("", Text(f"↳ {note}", style=style), "")
            if s.key == self._transfer_step and self._transfer_task is not None and not final:
                grid.add_row("", self._transfer.get_renderable(), "")
        self._overall.update(self._overall_task, completed=round(self.overall_fraction() * 100, 1))
        parts: list[Any] = [grid, Text(""), self._overall.get_renderable()]
        if final and total:
            parts.append(Text(f"Total time {duration(total)} (time spent answering questions is not counted)",
                              style="dim"))
        return Panel(Group(*parts), title=f"[bold]{self.title}", title_align="left", border_style="cyan")


# --------------------------------------------------------------------------- prompts
YES, NO = ("yes", "y"), ("no", "n")


def yes_no_error(text: str) -> bool | str:
    """True for an answer to a yes/no question; otherwise what to type."""
    return text.strip().lower() in YES + NO or "Answer yes or no (y/n), or press Ctrl+C to cancel."


# A checklist longer than this asks for a name pattern first and lists only the matches, so `a` (select all) takes
# what is listed. questionary's own type-to-filter is not used for checklists: its select-all also takes the
# entries the filter hides (an access setup could grant every datastore while the screen showed eight).
FILTER_AT = 12


def matches(label: str, pattern: str) -> bool:
    """A choice's label against a typed filter (case does not matter): shell-style with *, ? or [...], otherwise
    text the label contains. The name alone (the label before its details, e.g. a host's "  (16 cores)") is tried
    too, so 'esx*' and '*01' both work."""
    label, pattern = label.lower(), pattern.strip().lower()
    if not any(ch in pattern for ch in "*?["):
        return pattern in label
    return fnmatch.fnmatchcase(label, pattern) or fnmatch.fnmatchcase(label.split("  ")[0], pattern)

# Answers a retry never takes from the run it retries: a licence is accepted each time, and "_" fields are
# internal markers. Passwords are never kept at all, nor a URL holding a password or token (_hides_secret); the
# review is never answered for the user (no field name).
NOT_REPLAYED = ("ovf.accept_eula",)
_NO_FIT = object()


def to_json(value: Any) -> Any:
    """An answer as saved in a results file: plain values as they are, an inventory object by its name (a host,
    datastore, ...). Raises TypeError for anything else (not saved; the question is asked again)."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, list | tuple):
        return [to_json(v) for v in value]
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return {"name": name}
    raise TypeError(f"not saved: {type(value).__name__}")


def _hides_secret(value: Any) -> bool:
    """An answer holding a URL with a password or token in it (user:password@, or a query string such as a
    pre-signed signature), e.g. a URL typed at "Where is the VM image?": never saved, as in the logs, so a retry
    asks for it again. Text without an http(s) URL is never affected (a key's user@host, an e-mail address)."""
    if isinstance(value, str):
        return safe_url(value) != value
    if isinstance(value, list | tuple):
        return any(_hides_secret(v) for v in value)
    return False


def saved_answers(answers: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in answers.items():
        if k.startswith(("_", "--")) or k in NOT_REPLAYED or _hides_secret(v):
            continue
        try:
            out[k] = to_json(v)
        except TypeError:
            continue
    return out


def _same(value: Any, saved: Any) -> bool:
    try:
        return value == saved or to_json(value) == saved
    except TypeError:
        return False


class Prompter:
    """Interactive questions with a non-interactive mode for `--yes` / CI usage."""

    def __init__(self, interactive: bool, view: DeploymentView | None = None):
        self.interactive = interactive and sys.stdin.isatty()
        self.view = view
        self._requested_interactive = interactive
        # Answers by field name, so "Change my answers" can offer each previous answer as the default.
        self.answers: dict[str, Any] = {}
        self.previous: dict[str, Any] = {}
        # A retry's answers from the run it retries (`deploy --batch --retry-failed`): each question they still fit
        # is answered with them, shown, and not asked; "Change my answers" asks everything again.
        self.replay: dict[str, Any] = {}

    def would_ask(self, field_name: str) -> bool:
        """Is this question answered by someone: a person, or the run a retry repeats? Otherwise a default is
        taken where one is sensible (--yes)."""
        return self.interactive or field_name in self.replay

    def start_revision(self) -> None:
        """Ask the questions again with this pass's answers as the defaults."""
        self.previous, self.answers, self.replay = dict(self.answers), {}, {}

    def _replayed(self, field_name: str, question: str, fit: Callable[[Any], Any], shown=None) -> Any:
        """The answer the retried run gave, if it still fits (`fit` returns the value to use, or _NO_FIT);
        otherwise _NO_FIT and the question is asked."""
        if not field_name or field_name not in self.replay or field_name in NOT_REPLAYED:
            return _NO_FIT
        try:
            value = fit(self.replay[field_name])
        except (TypeError, ValueError, KeyError):
            return _NO_FIT
        if value is not _NO_FIT:
            text = shown(value) if shown else ("yes" if value is True else "no" if value is False else str(value))
            console.print(Text("  ✔ ", style="green") + Text(f"{question.rstrip(':?')}: ", style="bold")
                          + Text(text) + Text("  (as in the first run)", style="dim"))
            self._keep(field_name, value)
        return value

    def _prev(self, field_name: str, default: Any) -> Any:
        return self.previous.get(field_name, default) if field_name else default

    def _keep(self, field_name: str, value: Any) -> Any:
        if field_name:
            self.answers[field_name] = value
        return value

    def section(self, header: str):
        if self.view:
            return self.view.paused(header)
        console.print(Text(f"── {header} ", style="bold cyan"))
        return contextlib.nullcontext()

    @staticmethod
    def record(label: str, value: Any) -> None:
        """Echo a decision as a permanent log line."""
        console.print(Text("  ✔ ", style="green") + Text(f"{label}: ", style="bold") + Text(str(value)))

    def _need(self, field_name: str, question: str) -> None:
        if not self.interactive:
            if field_name.startswith("VMDEPLOY_"):  # answered by an environment variable (e.g. a token)
                hint = f"Set the {field_name} environment variable, or run without --yes to answer interactively."
            else:
                hint = (f"Set `{field_name}` in your manifest or pass it on the command line."
                        if field_name else "Run without --yes to answer interactively.")
            if self._requested_interactive and not sys.stdin.isatty():
                hint += " (stdin is not a terminal, so interactive prompts are unavailable.)"
            raise MissingInput(f"A value is needed for: {question}", hint=hint)

    def _waiting(self):
        return self.view.waiting() if self.view else contextlib.nullcontext()

    def _ask(self, q):
        # Every question pauses the live panel (a no-op inside a section, which already did): a prompt asked
        # outside a section used to be drawn under the 8 Hz refreshing panel.
        pause = self.view.paused() if self.view else contextlib.nullcontext()
        try:
            with pause, self._waiting():
                answer = q.unsafe_ask()  # raises on Ctrl-C (ask() also printed its own "Cancelled by user")
        except KeyboardInterrupt:
            raise UserAborted("Cancelled by user.") from None
        if answer is None:
            raise UserAborted("Cancelled by user.")
        return answer

    def text(self, question: str, *, default: str | None = None, field_name: str = "",
             validate: Callable[[str], bool | str] | None = None, assume_default: bool = False,
             secret: bool = False) -> str:
        if not secret:
            def fit(v):
                v = str(v) if isinstance(v, int | float) and not isinstance(v, bool) else v  # a saved number
                return v if isinstance(v, str) and (validate is None or validate(v) is True) else _NO_FIT
            got = self._replayed(field_name, question, fit)
            if got is not _NO_FIT:
                return got
        if not self.interactive:
            if default is not None and assume_default:
                return default
            self._need(field_name, question)
        if secret:  # never remembered
            return self._ask(questionary.password(question, validate=validate or (lambda v: bool(v) or "Required")))
        default = self._prev(field_name, default)
        return self._keep(field_name, self._ask(questionary.text(question, default=default or "", validate=validate)))

    def password(self, question: str, *, field_name: str = "") -> str:
        return self.text(question, field_name=field_name, secret=True)

    def confirm(self, question: str, *, default: bool = False, field_name: str = "",
                assume: bool | None = None) -> bool:
        """`assume` is what non-interactive mode answers; None means non-interactive must fail."""
        got = self._replayed(field_name, question, lambda v: v if isinstance(v, bool) else _NO_FIT)
        if got is not _NO_FIT:
            return got
        if not self.interactive:
            if assume is None:
                self._need(field_name, question)
            return bool(assume)
        # Typed, never a single keypress: questionary's confirm took the first y/n anywhere in stray typing and
        # Enter took the default, so a question could be answered by accident. Only yes/y/no/n are accepted.
        default = bool(self._prev(field_name, default))
        shown = f"{question} (yes/no, {'before' if field_name in self.previous else 'suggested'}: "                 f"{'yes' if default else 'no'})"
        answer = self._ask(questionary.text(shown, validate=yes_no_error))
        return self._keep(field_name, answer.strip().lower() in YES)

    def select(self, question: str, choices: Sequence[tuple], *, default: Any = None,
               field_name: str = "", assume_default: bool = False, auto_single: bool = True,
               answer_key: str = "") -> Any:
        """`choices` is a list of (label, value) or (label, value, description). Returns the value. A description
        is shown below the list for the highlighted choice only (long vendor texts no longer run off the screen).
        When there is exactly one possible answer (e.g. a host with a single datastore) it is taken without
        asking, unless auto_single=False.

        `answer_key`: what the answer is kept, offered again and replayed under, when that is not `field_name`
        alone: several questions answered by one manifest field (each host's datastore, all of them from
        batch.targets[k].datastore) or a question that is not the field itself (how hostnames are chosen, before
        the batch.hostname pattern). `field_name` still names the manifest field a --yes run needs."""
        if not choices:
            raise MissingInput(f"No valid options available for: {question}")
        if len(choices) == 1 and auto_single:
            return choices[0][1]
        key = answer_key or field_name
        match = {}

        def fit(saved):
            hit = next((c for c in choices if _same(c[1], saved)), None)
            if hit is None:
                return _NO_FIT
            match["label"] = hit[0]
            return hit[1]
        got = self._replayed(key, question, fit, shown=lambda v: match["label"])
        if got is not _NO_FIT:
            return got
        if not self.interactive:
            if assume_default and default is not None:
                return default
            self._need(field_name, question)
        if any(c[1] is None for c in choices):
            raise ValueError("select() choices must not use None as a value (questionary returns the title instead)")
        qchoices = []
        for c in choices:
            desc = c[2] if len(c) > 2 and c[2] else None
            qchoices.append(questionary.Choice(title=c[0], value=c[1], description=desc)
                            if desc and _CHOICE_DESCRIPTIONS else questionary.Choice(title=c[0], value=c[1]))
        default = self._prev(key, default)
        default_choice = next((c for c in qchoices if c.value == default), None)
        return self._keep(key, self._ask(questionary.select(
            question, choices=qchoices, default=default_choice, use_search_filter=len(qchoices) > 12,
            use_jk_keys=False)))

    def checkbox(self, question: str, choices: Sequence[tuple], *, field_name: str = "",
                 minimum: int = 1) -> list[Any]:
        """Pick one or more of (label, value) (or none, with minimum=0). A single required choice is taken
        without asking. A third element, when set, greys the choice out with that reason (e.g. "maintenance mode"):
        shown, so the user knows why it cannot be picked. A list longer than FILTER_AT asks for a name pattern
        first and lists only the matches (a retry's saved answer is tried against the whole list before that)."""
        usable = [c for c in choices if not (len(c) > 2 and c[2])]
        if not usable:
            if minimum == 0:
                return []
            raise MissingInput(f"No valid options available for: {question}")
        if len(usable) == 1 and len(choices) == 1 and minimum >= 1:
            return [usable[0][1]]
        labels = {}

        def fit(saved):
            picked = [next((c for c in usable if _same(c[1], v)), None) for v in saved]
            if not isinstance(saved, list) or None in picked or len(picked) < minimum:
                return _NO_FIT  # e.g. a host that is gone or in maintenance mode now: asked again
            labels["text"] = ", ".join(c[0].split("  ")[0] for c in picked)  # the name, not its free space
            return [c[1] for c in picked]
        got = self._replayed(field_name, question, fit, shown=lambda v: labels["text"])
        if got is not _NO_FIT:
            return got
        if not self.interactive and minimum == 0:
            return []
        if not self.interactive:
            self._need(field_name, question)
        listed = self._narrowed(question, choices) if len(choices) > FILTER_AT else list(choices)
        qchoices = [questionary.Choice(title=c[0], value=c[1], disabled=c[2] if len(c) > 2 and c[2] else None)
                    for c in listed]
        # Say how to pick many at once (large vCenters list dozens of hosts or datastores): questionary has the
        # keys, but its own hint was replaced by ours. `a` takes every entry listed, and only those.
        return self._keep(field_name, self._ask(questionary.checkbox(
            question, choices=qchoices, instruction="(space selects, a selects all listed, i inverts, Enter confirms)",
            validate=lambda picked: len(picked) >= minimum or f"Pick at least {minimum} (space selects, a selects "
                                                              "all listed)")))

    def _narrowed(self, question: str, choices: Sequence[tuple]) -> list[tuple]:
        """The entries of a long checklist that match a pattern typed first (Enter: all of them). A pattern that
        leaves nothing to pick is asked again."""
        what = question.rstrip(":?").strip()
        while True:
            pattern = self._ask(questionary.text(f"{what}: {len(choices)} to choose from. Only list those matching "
                                                 "(e.g. esx-east-* or nvme; Enter lists all):")).strip()
            if pattern in ("", "*"):
                return list(choices)
            listed = [c for c in choices if matches(c[0], pattern)]
            if any(not (len(c) > 2 and c[2]) for c in listed):
                return listed
            console.print(Text(f"  Nothing that can be picked matches '{pattern}': try another, or press Enter to "
                               "list all.", style="yellow"))

    def numbered(self, question: str, choices: Sequence[tuple[str, Any]], *, default: Any,
                 field_name: str = "") -> Any:
        """Plain numbered menu on one line, e.g. `1) Trust for this session   2) ...   3) Cancel [default]`.
        Works in any terminal (no cursor control needed); Enter selects the default."""
        if not self.interactive:
            self._need(field_name, question)
        labels = []
        default_no = None
        for i, (label, value) in enumerate(choices, 1):
            mark = " [default]" if value == default else ""
            if value == default:
                default_no = str(i)
            labels.append(f"{i}) {label}{mark}")
        console.print("   ".join(labels), markup=False, highlight=False)
        valid = {str(i): v for i, (_, v) in enumerate(choices, 1)}
        while True:
            try:
                with self._waiting():
                    raw = console.input(f"{question} ").strip()
            except (KeyboardInterrupt, EOFError):
                raise UserAborted("Cancelled by user.") from None
            raw = raw or (default_no or "")
            if raw in valid:
                return valid[raw]
            console.print(f"Please enter a number from 1 to {len(choices)}.")

    def integer(self, question: str, *, default: int | None = None, minimum: int = 1,
                maximum: int | None = None, field_name: str = "") -> int:
        def _validate(v: str) -> bool | str:
            if not v.strip().isdigit():
                return "Enter a whole number"
            n = int(v)
            if n < minimum:
                return f"Must be at least {minimum}"
            if maximum is not None and n > maximum:
                return f"Must be at most {maximum}"
            return True

        return int(self.text(question, default=str(default) if default is not None else None,
                             validate=_validate, field_name=field_name))


def info(msg: str) -> None:
    console.print(msg)


def warn(msg: str) -> None:
    console.print(Text("! ", style="bold yellow") + Text(msg, style="yellow"))


def error(msg: str, hint: str | None = None) -> None:
    console.print(Text("✖ ", style="bold red") + Text(msg, style="red"))
    if hint:
        console.print(Text("  hint: ", style="bold") + Text(hint))
