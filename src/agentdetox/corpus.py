from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

TEXT_SUFFIXES = {".txt", ".md", ".markdown", ".html", ".htm", ".rst"}


@dataclass
class Doc:
    id: str
    text: str
    source: str
    meta: dict = field(default_factory=dict)


def load_corpus(
    path: Path,
    text_field: str = "text",
    id_field: str = "id",
    chunk_chars: int = 0,
    skipped: dict[str, int] | None = None,
) -> list[Doc]:
    """The documents under `path`. What cannot be read is left out and counted in `skipped`
    (by kind) instead of ending the scan: one bad line in an export is not a reason to scan
    nothing. A file that is a symbolic link is not followed out of the folder."""
    skipped = {} if skipped is None else skipped

    def skip(what: str) -> None:
        skipped[what] = skipped.get(what, 0) + 1

    if path.is_file():
        files = [path]
    else:
        files = []
        for p in sorted(path.rglob("*")):
            if p.is_symlink():
                skip("symbolic link(s), not followed")
            elif p.is_file():
                files.append(p)
    docs: list[Doc] = []
    for p in files:
        try:
            for doc in _load_file(p, path, text_field, id_field, skip):
                docs.extend(chunk_doc(doc, chunk_chars) if chunk_chars > 0 else [doc])
        except OSError:
            skip("file(s) that could not be read")
    return docs


def _load_file(p: Path, root: Path, text_field: str, id_field: str, skip=lambda what: None):
    suffix = p.suffix.lower()
    rel = p.name if root.is_file() else str(p.relative_to(root))
    if suffix == ".jsonl":
        with p.open(encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except (ValueError, RecursionError):
                    rec = None
                if not isinstance(rec, dict):
                    skip("line(s) that are not JSON objects")
                    continue
                text = rec.get(text_field)
                if not isinstance(text, str):
                    continue
                doc_id = str(rec.get(id_field, f"{rel}:{lineno}"))
                yield Doc(id=doc_id, text=text, source=f"{rel}:{lineno}")
    elif suffix in TEXT_SUFFIXES:
        yield Doc(id=rel, text=p.read_text(encoding="utf-8", errors="replace"), source=rel)


def chunk_doc(doc: Doc, max_chars: int) -> list[Doc]:
    """Split on blank lines, packing paragraphs into chunks of at most max_chars."""
    paras = [p.strip() for p in doc.text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    buf = ""
    for para in paras:
        if buf and len(buf) + len(para) + 2 > max_chars:
            chunks.append(buf)
            buf = ""
        buf = f"{buf}\n\n{para}" if buf else para
    if buf:
        chunks.append(buf)
    if len(chunks) <= 1:
        return [doc]
    return [
        Doc(id=f"{doc.id}#{i}", text=c, source=doc.source, meta={**doc.meta, "chunk": i})
        for i, c in enumerate(chunks)
    ]
