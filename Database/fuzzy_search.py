"""Simple fuzzy search helpers for matching short queries."""

from __future__ import annotations

import difflib
import re
from typing import Iterable, Tuple

from Database.wordnet_synonyms import get_synonyms_for_token


def normalize_text(value: str) -> str:
    """Lowercase text and remove punctuation for fuzzy matching."""

    if not value:
        return ""
    cleaned = re.sub(r"[^a-z0-9]+", " ", value.lower())
    return " ".join(cleaned.split())


def fuzzy_score(query: str, text: str) -> float:
    """Return a similarity score between 0.0 and 1.0 for query vs text."""

    normalized_query = normalize_text(query)
    normalized_text = normalize_text(text)
    if not normalized_query or not normalized_text:
        return 0.0
    if normalized_query in normalized_text:
        return 1.0

    query_tokens = normalized_query.split()
    text_tokens = normalized_text.split()
    if not text_tokens:
        return 0.0

    scores = []
    for token in query_tokens:
        best = 0.0
        candidates = get_synonyms_for_token(token)
        if not candidates:
            candidates = {token}
        for candidate in candidates:
            for word in text_tokens:
                if candidate in word:
                    best = 1.0
                    break
                ratio = difflib.SequenceMatcher(None, candidate, word).ratio()
                if ratio > best:
                    best = ratio
            if best == 1.0:
                break
        scores.append(best)
    return sum(scores) / len(scores)


def best_fuzzy_score(query: str, fields: Iterable[str]) -> float:
    """Return the best fuzzy score for a query across multiple fields."""

    scores = [fuzzy_score(query, field) for field in fields if field]
    return max(scores) if scores else 0.0


def matches_fuzzy(query: str, fields: Iterable[str], threshold: float) -> Tuple[bool, float]:
    """Check if any field matches the query above the threshold."""

    if not query:
        return True, 1.0
    score = best_fuzzy_score(query, fields)
    return score >= threshold, score
