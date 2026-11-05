#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""mdBook preprocessor: expand {{#include}} and rewrite relative links/images
so they resolve from the chapter path (or become in-book / GitHub targets).

mdBook's built-in links preprocessor expands includes but does not rebase
relative URLs inside the included text. This preprocessor runs *before*
``links``, expands includes itself, and remaps links using a source→chapter
map derived from the book's own include stubs plus a few static entries.

mdBook 0.4 renders a chapter file named ``README.md`` as ``index.html`` in
that directory, but leaves markdown links to ``README.md`` as
``README.html``. Whenever this preprocessor emits a link to a README
chapter, it therefore targets ``index.html`` (never ``README.md`` /
``README.html``). The same rewrite is applied to handwritten chapter
links that point at in-book ``README.md`` files.

Usage (book.toml; mdBook runs the command with the repository root as cwd
when invoked as ``mdbook build docs``):
  [preprocessor.include-map]
  command = "python3 docs/mdbook-include-map.py"
  before = ["links"]

Checks (from the repository root):
  python3 docs/mdbook-include-map.py --check       # source / include map
  python3 docs/mdbook-include-map.py --check-html  # rendered docs/book
"""
from __future__ import annotations

import json
import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

DOCS_DIR = Path(__file__).resolve().parent
REPO_ROOT = DOCS_DIR.parent
SRC_DIR = DOCS_DIR / "src"
BOOK_DIR = DOCS_DIR / "book"
GITHUB_BLOB = "https://github.com/wiresock/awg-server-tools/blob/main/"
SITE_URL_PREFIX = "/awg-server-tools/"

INCLUDE_RE = re.compile(
    r"\{\{#include\s+([^}\s]+)(?::(\d+)(?::-?(\d+))?)?\s*\}\}"
)
# Markdown links and images: optional !, [text](url) or [text](<url>)
MD_LINK_RE = re.compile(
    r"(!?\[([^\]]*)\]\()<?([^)\s>]+)>?((?:\s+\"[^\"]*\")?\))"
)

# Extra source-file → book-chapter mappings not expressed as {{#include}} stubs
# (authored pages, or alternate names). Paths are relative to the repo root.
EXTRA_SOURCE_TO_CHAPTER = {
    # proxy README is authored in-book, not an include of amneziawg-proxy/doc/README.md
}


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def build_source_to_chapter() -> dict[Path, Path]:
    """Map absolute source file → absolute chapter file under docs/src."""
    mapping: dict[Path, Path] = {}
    for chapter in SRC_DIR.rglob("*.md"):
        if chapter.name == "SUMMARY.md":
            continue
        text = read_text(chapter)
        for m in INCLUDE_RE.finditer(text):
            rel = m.group(1).strip()
            source = (chapter.parent / rel).resolve()
            if source.exists():
                mapping[source] = chapter
    for src_rel, ch_rel in EXTRA_SOURCE_TO_CHAPTER.items():
        mapping[(REPO_ROOT / src_rel).resolve()] = (SRC_DIR / ch_rel).resolve()
    return mapping


def slice_lines(text: str, start: str | None, end: str | None) -> str:
    if not start:
        return text
    lines = text.splitlines(keepends=True)
    s = int(start) - 1
    e = int(end) if end else len(lines)
    return "".join(lines[s:e])


def rel_between(from_chapter: Path, to_path: Path) -> str:
    """POSIX relative path from from_chapter's directory to to_path."""
    return Path(os.path.relpath(to_path, start=from_chapter.parent)).as_posix()


def href_for_chapter(from_chapter: Path, to_chapter: Path) -> str:
    """Href for an in-book chapter, accounting for README.md → index.html."""
    if to_chapter.name == "README.md":
        # mdBook renders README.md as index.html; do not emit README.md/html.
        return rel_between(from_chapter, to_chapter.parent / "index.html")
    return rel_between(from_chapter, to_chapter)


def github_url(repo_relative: Path, anchor: str) -> str:
    url = GITHUB_BLOB + repo_relative.as_posix()
    if anchor:
        url += "#" + anchor
    return url


def rewrite_url(
    url: str,
    *,
    include_source: Path,
    chapter: Path,
    source_to_chapter: dict[Path, Path],
) -> str:
    if url.startswith(("http://", "https://", "mailto:", "irc:")):
        return url
    if url.startswith("#"):
        # Same-document anchor inside the included text — keep as-is.
        return url

    path_part, _, anchor = url.partition("#")
    target = (include_source.parent / path_part).resolve()

    # Prefer an in-book chapter for the same source file.
    if target in source_to_chapter:
        dest = source_to_chapter[target]
        new_path = href_for_chapter(chapter, dest)
        return f"{new_path}#{anchor}" if anchor else new_path

    # Images (and other binaries) already committed under docs/src/: point at them.
    if target.exists() and target.is_file():
        try:
            under_src = target.relative_to(SRC_DIR)
            dest = SRC_DIR / under_src
            if dest.suffix == ".md":
                new_path = href_for_chapter(chapter, dest)
            else:
                new_path = rel_between(chapter, dest)
            return f"{new_path}#{anchor}" if anchor else new_path
        except ValueError:
            pass

        # Known screenshot reuse: amneziawg-web screenshots → docs/src/images/
        try:
            rel_repo = target.relative_to(REPO_ROOT)
        except ValueError:
            rel_repo = None
        if rel_repo is not None:
            if rel_repo.parts[:3] == ("amneziawg-web", "docs", "screenshots"):
                mirrored = SRC_DIR / "images" / rel_repo.name
                if mirrored.exists():
                    new_path = rel_between(chapter, mirrored)
                    return f"{new_path}#{anchor}" if anchor else new_path
            # Not in the book: stable GitHub blob link (works for LICENSE, pin.env, …).
            return github_url(rel_repo, anchor)

    # Missing target: still emit a GitHub URL from the logical join so the
    # site does not keep a doomed relative path.
    try:
        logical = (include_source.parent / path_part).resolve()
        rel_repo = logical.relative_to(REPO_ROOT)
        return github_url(rel_repo, anchor)
    except Exception:
        return url


def rewrite_markdown(
    text: str,
    *,
    include_source: Path,
    chapter: Path,
    source_to_chapter: dict[Path, Path],
) -> str:
    def repl(m: re.Match[str]) -> str:
        prefix, url, suffix = m.group(1), m.group(3), m.group(4)
        new_url = rewrite_url(
            url,
            include_source=include_source,
            chapter=chapter,
            source_to_chapter=source_to_chapter,
        )
        return f"{prefix}{new_url}{suffix}"

    return MD_LINK_RE.sub(repl, text)


def rewrite_readme_chapter_links(chapter: Path, text: str) -> str:
    """Rewrite handwritten links to in-book README.md chapters as index.html."""

    def repl(m: re.Match[str]) -> str:
        prefix, url, suffix = m.group(1), m.group(3), m.group(4)
        if url.startswith(("http://", "https://", "mailto:", "irc:", "#")):
            return m.group(0)
        path_part, _, anchor = url.partition("#")
        if not path_part:
            return m.group(0)
        target = (chapter.parent / path_part).resolve()
        try:
            target.relative_to(SRC_DIR)
        except ValueError:
            return m.group(0)
        if target.name == "README.md" and target.is_file():
            new_path = href_for_chapter(chapter, target)
            new_url = f"{new_path}#{anchor}" if anchor else new_path
            return f"{prefix}{new_url}{suffix}"
        return m.group(0)

    return MD_LINK_RE.sub(repl, text)


def expand_includes(
    chapter: Path,
    text: str,
    source_to_chapter: dict[Path, Path],
    depth: int = 0,
) -> str:
    if depth > 8:
        return text

    def repl(m: re.Match[str]) -> str:
        rel = m.group(1).strip()
        start, end = m.group(2), m.group(3)
        source = (chapter.parent / rel).resolve()
        if not source.exists():
            return m.group(0)
        body = slice_lines(read_text(source), start, end)
        body = expand_includes_in_source(
            source, body, chapter, source_to_chapter, depth + 1
        )
        body = rewrite_markdown(
            body,
            include_source=source,
            chapter=chapter,
            source_to_chapter=source_to_chapter,
        )
        return body

    return INCLUDE_RE.sub(repl, text)


def expand_includes_in_source(
    source: Path,
    text: str,
    chapter: Path,
    source_to_chapter: dict[Path, Path],
    depth: int,
) -> str:
    """Expand nested {{#include}} found inside an already-included file."""
    if depth > 8:
        return text

    def repl(m: re.Match[str]) -> str:
        rel = m.group(1).strip()
        start, end = m.group(2), m.group(3)
        nested = (source.parent / rel).resolve()
        if not nested.exists():
            return m.group(0)
        body = slice_lines(read_text(nested), start, end)
        body = expand_includes_in_source(
            nested, body, chapter, source_to_chapter, depth + 1
        )
        body = rewrite_markdown(
            body,
            include_source=nested,
            chapter=chapter,
            source_to_chapter=source_to_chapter,
        )
        return body

    return INCLUDE_RE.sub(repl, text)


def process_chapter_content(
    chapter_path: Path | None, content: str, source_to_chapter: dict[Path, Path]
) -> str:
    if chapter_path is None:
        return content
    chapter = (SRC_DIR / chapter_path).resolve()
    if not chapter.exists():
        return content
    content = expand_includes(chapter, content, source_to_chapter)
    content = rewrite_readme_chapter_links(chapter, content)
    return content


def walk_items(items: list, source_to_chapter: dict[Path, Path]) -> None:
    for item in items:
        if "Chapter" in item:
            ch = item["Chapter"]
            path = ch.get("path")
            ch["content"] = process_chapter_content(
                Path(path) if path else None, ch.get("content", ""), source_to_chapter
            )
            walk_items(ch.get("sub_items") or [], source_to_chapter)


def run_preprocessor() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "supports":
        sys.exit(0)

    raw = sys.stdin.read()
    _context, book = json.loads(raw)
    source_to_chapter = build_source_to_chapter()
    walk_items(book.get("sections") or [], source_to_chapter)
    json.dump(book, sys.stdout)


def _link_target_exists(chapter: Path, path_part: str) -> bool:
    """Whether a rewritten markdown href resolves for the source checker."""
    target = (chapter.parent / path_part).resolve()
    if target.exists():
        return True
    # Preprocessor emits index.html for README.md chapters; accept that.
    if path_part.endswith("index.html") or target.name == "index.html":
        readme = target.parent / "README.md"
        try:
            readme.relative_to(SRC_DIR)
        except ValueError:
            return False
        return readme.is_file()
    return False


def static_check() -> int:
    """Expand includes as the preprocessor would and count broken relative targets."""
    source_to_chapter = build_source_to_chapter()
    link_re = re.compile(r"!?\[([^\]]*)\]\(([^)]+)\)")
    broken = []
    ok = []
    external = []
    for chapter in sorted(SRC_DIR.rglob("*.md")):
        if chapter.name == "SUMMARY.md":
            continue
        rel = chapter.relative_to(SRC_DIR)
        expanded = process_chapter_content(rel, read_text(chapter), source_to_chapter)
        for m in link_re.finditer(expanded):
            url = m.group(2).strip()
            if " " in url and not url.startswith("<"):
                url = url.split()[0]
            url = url.strip("<>")
            if url.startswith(("http://", "https://", "mailto:", "irc:")):
                external.append((chapter, url))
                continue
            if url.startswith("#"):
                continue
            path_part, _, _anchor = url.partition("#")
            if not path_part:
                continue
            if _link_target_exists(chapter, path_part):
                ok.append((chapter, url))
            else:
                broken.append((str(rel), url))
    print(
        f"ok_links={len(ok)} broken={len(broken)} external={len(external)} "
        f"mapped_sources={len(source_to_chapter)}"
    )
    for ch, url in broken:
        print(f"BROKEN {ch} -> {url}")
    return 1 if broken else 0


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = {k: v or "" for k, v in attrs}
        if tag == "a" and "href" in d:
            self.urls.append(d["href"])
        if tag == "img" and "src" in d:
            self.urls.append(d["src"])


def check_html(book_dir: Path | None = None) -> int:
    """Fail if any in-book relative link/image in rendered HTML is missing."""
    root = (book_dir or BOOK_DIR).resolve()
    if not root.is_dir():
        print(f"error: book output not found at {root} (run: mdbook build docs)", file=sys.stderr)
        return 2

    broken: list[tuple[str, str]] = []
    ok = 0
    for html in sorted(root.rglob("*.html")):
        parser = _LinkCollector()
        parser.feed(read_text(html))
        for url in parser.urls:
            if not url or url.startswith(
                ("http://", "https://", "mailto:", "irc:", "data:", "javascript:")
            ):
                continue
            if url.startswith("#"):
                continue
            path_part, _, _ = url.partition("#")
            if not path_part:
                continue
            if path_part.startswith("/"):
                rel = path_part
                if rel.startswith(SITE_URL_PREFIX):
                    rel = rel[len(SITE_URL_PREFIX) :]
                else:
                    rel = rel.lstrip("/")
                target = (root / rel).resolve()
            else:
                target = (html.parent / path_part).resolve()
            try:
                target.relative_to(root)
            except ValueError:
                broken.append((str(html.relative_to(root)), url))
                continue
            if target.exists():
                ok += 1
            else:
                broken.append((str(html.relative_to(root)), url))

    print(f"ok_links={ok} broken={len(broken)} book={root}")
    for page, url in broken:
        print(f"BROKEN {page} -> {url}")
    return 1 if broken else 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        sys.exit(static_check())
    if len(sys.argv) > 1 and sys.argv[1] == "--check-html":
        book = Path(sys.argv[2]) if len(sys.argv) > 2 else None
        sys.exit(check_html(book))
    run_preprocessor()
