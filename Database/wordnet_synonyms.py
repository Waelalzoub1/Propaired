"""WordNet-based synonym lookup for search queries."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Set

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DICT_DIR = Path(os.environ.get("HELPER_DICT_DIR", str(PROJECT_ROOT / "dict")))

_SYNONYM_MAP: Dict[str, Set[str]] | None = None


def _normalize_term(term: str) -> str:
    cleaned = re.sub(r"[^a-z0-9 ]+", " ", term.lower())
    return " ".join(cleaned.split())


def _load_wordnet_synonyms() -> Dict[str, Set[str]]:
    global _SYNONYM_MAP
    if _SYNONYM_MAP is not None:
        return _SYNONYM_MAP

    synonyms: Dict[str, Set[str]] = {}
    if not DICT_DIR.exists():
        _SYNONYM_MAP = synonyms
        return _SYNONYM_MAP

    for pos in ("noun", "verb", "adj", "adv"):
        data_path = DICT_DIR / f"data.{pos}"
        if not data_path.exists():
            continue
        with data_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if not line or not line[0].isdigit():
                    continue
                parts = line.strip().split()
                if len(parts) < 5:
                    continue
                try:
                    word_count = int(parts[3], 16)
                except ValueError:
                    continue
                words = []
                index = 4
                for _ in range(word_count):
                    if index >= len(parts):
                        break
                    word = _normalize_term(parts[index].replace("_", " "))
                    if word:
                        words.append(word)
                    index += 2
                if not words:
                    continue
                for word in words:
                    bucket = synonyms.setdefault(word, set())
                    bucket.update(words)

    _SYNONYM_MAP = synonyms
    return _SYNONYM_MAP


def get_synonyms_for_token(token: str, limit: int = 12) -> Set[str]:
    """Return a set of synonyms for a single query token."""

    normalized = _normalize_term(token)
    if not normalized:
        return set()

    synonyms = _load_wordnet_synonyms().get(normalized, set())
    single_word = {syn for syn in synonyms if " " not in syn}
    single_word.add(normalized)

    if limit and len(single_word) > limit:
        return set(sorted(single_word)[:limit])
    return single_word
