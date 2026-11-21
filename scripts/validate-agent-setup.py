#!/usr/bin/env python3
"""Check that agent entry points and skill mirrors stay in sync."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
MIRRORS = (ROOT / ".claude" / "skills", ROOT / ".opencode" / "skills")
ENTRY_POINTS = (
    "CLAUDE.md",
    "GEMINI.md",
    "CONVENTIONS.md",
    ".windsurfrules",
    ".cursor/rules/oxsession.mdc",
    ".github/copilot-instructions.md",
)


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def canonical_skills(errors: list[str]) -> set[str]:
    skills: set[str] = set()
    files = sorted(SKILLS.glob("*/SKILL.md"))
    if not files:
        fail(errors, "skills/: no <name>/SKILL.md playbooks found")

    for path in files:
        name = path.parent.name
        skills.add(name)
        content = path.read_text(encoding="utf-8")
        if not content.startswith("---\n"):
            fail(errors, f"{path.relative_to(ROOT)}: missing YAML frontmatter")
            continue

        frontmatter, separator, _ = content[4:].partition("\n---\n")
        if not separator:
            fail(errors, f"{path.relative_to(ROOT)}: unterminated YAML frontmatter")
            continue

        fields = {}
        for line in frontmatter.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields[key.strip()] = value.strip()
        if fields.get("name") != name:
            fail(errors, f"{path.relative_to(ROOT)}: name must be {name!r}")
        if not fields.get("description"):
            fail(errors, f"{path.relative_to(ROOT)}: description must be non-empty")

    return skills


def check_index(skills: set[str], errors: list[str]) -> None:
    index = ROOT / "skills" / "README.md"
    if not index.is_file():
        fail(errors, "skills/README.md: missing skill index")
        return
    content = index.read_text(encoding="utf-8")
    indexed: set[str] = set()
    for name, target in re.findall(r"\[`([^`]+)`\]\(([^)]+/SKILL\.md)\)", content):
        if not target.startswith("../"):
            indexed.add(name)
        if not (index.parent / target).resolve().is_file():
            fail(errors, f"skills/README.md: broken skill link {target!r}")

    if indexed != skills:
        missing = sorted(skills - indexed)
        stale = sorted(indexed - skills)
        if missing:
            fail(errors, f"skills/README.md: missing skill entries: {', '.join(missing)}")
        if stale:
            fail(errors, f"skills/README.md: entries without playbooks: {', '.join(stale)}")


def check_mirrors(skills: set[str], errors: list[str]) -> None:
    for mirror in MIRRORS:
        if not mirror.is_dir():
            fail(errors, f"{mirror.relative_to(ROOT)}: missing skill mirror directory")
            continue

        entries = {entry.name for entry in mirror.iterdir()}
        if entries != skills:
            missing = sorted(skills - entries)
            extra = sorted(entries - skills)
            if missing:
                fail(errors, f"{mirror.relative_to(ROOT)}: missing mirrors: {', '.join(missing)}")
            if extra:
                fail(errors, f"{mirror.relative_to(ROOT)}: stale mirrors: {', '.join(extra)}")

        for name in sorted(skills & entries):
            link = mirror / name
            canonical = SKILLS / name
            if not link.is_symlink():
                fail(errors, f"{link.relative_to(ROOT)}: expected a symlink to skills/{name}")
                continue
            try:
                if link.resolve(strict=True) != canonical.resolve(strict=True):
                    fail(errors, f"{link.relative_to(ROOT)}: must point to skills/{name}")
            except (OSError, RuntimeError):
                fail(errors, f"{link.relative_to(ROOT)}: broken or cyclic symlink")


def check_entry_points(errors: list[str]) -> None:
    agents = ROOT / "AGENTS.md"
    if not agents.is_file():
        fail(errors, "AGENTS.md: missing canonical agent instructions")
    else:
        content = agents.read_text(encoding="utf-8")
        for required in ("skills/", "Definition of done", "dependency"):
            if required.casefold() not in content.casefold():
                fail(errors, f"AGENTS.md: expected to mention {required!r}")
        for relative in ENTRY_POINTS:
            if relative not in content:
                fail(errors, f"AGENTS.md: entry-point table is missing {relative!r}")

    for relative in ENTRY_POINTS:
        path = ROOT / relative
        if not path.is_file():
            fail(errors, f"{relative}: missing agent entry point")
            continue
        content = path.read_text(encoding="utf-8")
        if "AGENTS.md" not in content:
            fail(errors, f"{relative}: must point to AGENTS.md")
        if "skills/" not in content:
            fail(errors, f"{relative}: must point to the canonical skills/")


def main() -> int:
    errors: list[str] = []
    skills = canonical_skills(errors)
    check_index(skills, errors)
    check_mirrors(skills, errors)
    check_entry_points(errors)

    if errors:
        print("Agent setup validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        f"Agent setup OK: {len(skills)} skills, "
        f"{len(MIRRORS)} mirrors, {len(ENTRY_POINTS)} entry points"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
