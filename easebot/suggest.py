"""Turn an original/fixed pair into GitHub suggested-change hunks, and work out which of them can be
posted as review comments (GitHub only accepts comments on lines that appear in the PR diff)."""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass
class Suggestion:
    start: int  # 1-based, inclusive, line numbers in the ORIGINAL (PR head) file
    end: int
    replacement: list[str]

    def body(self) -> str:
        fence = "````" if any(l.startswith("```") for l in self.replacement) else "```"
        return f"{fence}suggestion\n" + "".join(l + "\n" for l in self.replacement) + fence


def suggestions(original: str, fixed: str, merge_gap: int = 2) -> list[Suggestion]:
    a, b = original.splitlines(), fixed.splitlines()
    ops = [op for op in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes() if op[0] != "equal"]
    # Merge edits separated by only a few unchanged lines into one suggestion.
    groups: list[list[tuple]] = []
    for op in ops:
        if groups and op[1] - groups[-1][-1][2] <= merge_gap:
            groups[-1].append(op)
        else:
            groups.append([op])
    out = []
    for g in groups:
        i1, i2 = g[0][1], g[-1][2]
        j1, j2 = g[0][3], g[-1][4]
        if i1 == i2:  # pure insertion: anchor on a neighbouring original line
            if i1 > 0:
                out.append(Suggestion(i1, i1, [a[i1 - 1]] + b[j1:j2]))
            elif a:
                out.append(Suggestion(1, 1, b[j1:j2] + [a[0]]))
            continue
        out.append(Suggestion(i1 + 1, i2, b[j1:j2]))
    return out


def commentable_hunks(patch: str | None) -> list[set[int]]:
    """Right-side line numbers visible in each hunk of a GitHub file patch."""
    hunks: list[set[int]] = []
    if not patch:
        return hunks
    line = 0
    for raw in patch.splitlines():
        m = HUNK.match(raw)
        if m:
            line = int(m.group(1))
            hunks.append(set())
            continue
        if not hunks or raw.startswith("\\"):
            continue
        if raw.startswith("-"):
            continue
        hunks[-1].add(line)
        line += 1
    return hunks


def split_postable(sugs: list[Suggestion], patch: str | None):
    hunks = commentable_hunks(patch)
    postable, other = [], []
    for s in sugs:
        rng = set(range(s.start, s.end + 1))
        (postable if any(rng <= h for h in hunks) else other).append(s)
    return postable, other


def unified(original: str, fixed: str, path: str) -> str:
    return "".join(difflib.unified_diff(original.splitlines(True), fixed.splitlines(True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))
