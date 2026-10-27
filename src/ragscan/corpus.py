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
) -> list[Doc]:
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    docs: list[Doc] = []
    for p in files:
        for doc in _load_file(p, path, text_field, id_field):
            docs.extend(chunk_doc(doc, chunk_chars) if chunk_chars > 0 else [doc])
    return docs


def _load_file(p: Path, root: Path, text_field: str, id_field: str):
    suffix = p.suffix.lower()
    rel = p.name if root.is_file() else str(p.relative_to(root))
    if suffix == ".jsonl":
        with p.open(encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
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
