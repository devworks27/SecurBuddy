"""Loading and indexing of the golden dataset of labelled attack samples."""

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("securbuddy")

_WORD_REGEX = re.compile(r"[a-z0-9]{3,}")


class Dataset:
    """Loads the golden dataset and supports exact lookup plus similarity search."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.cases: list[dict[str, Any]] = []
        self._word_sets: list[set[str]] = []
        self.reload()

    def reload(self) -> None:
        """Re-read the dataset from disk; never raises."""
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            logger.warning("Dataset not found at %s", self.path)
            self.cases = []
            self._word_sets = []
            return
        except json.JSONDecodeError:
            logger.exception("Dataset at %s is not valid JSON", self.path)
            self.cases = []
            self._word_sets = []
            return

        if not isinstance(raw, list):
            logger.error("Dataset root must be a JSON array, got %s", type(raw).__name__)
            self.cases = []
            self._word_sets = []
            return

        self.cases = [c for c in raw if isinstance(c, dict)]
        self._word_sets = [set(_WORD_REGEX.findall(str(c.get("raw_input", "")).lower())) for c in self.cases]
        logger.info("Loaded %d dataset cases from %s", len(self.cases), self.path)

    def __len__(self) -> int:
        return len(self.cases)

    def get(self, case_id: str) -> dict[str, Any] | None:
        """Return a case by id, or None."""
        for case in self.cases:
            if case.get("id") == case_id:
                return case
        return None

    def public_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Shape a raw case into the payload the frontend consumes."""
        return {
            "id": str(case.get("id", "")),
            "type": str(case.get("type", "unknown")),
            "description": str(case.get("description", "")),
            "raw_input": str(case.get("raw_input", "")),
        }

    def listing(self) -> list[dict[str, Any]]:
        """Every case, without the raw text, for the sidebar picker."""
        return [
            {
                "id": str(c.get("id", "")),
                "type": str(c.get("type", "unknown")),
                "description": str(c.get("description", "")),
            }
            for c in self.cases
        ]

    def find_similar(self, text: str, exclude_id: str | None = None) -> tuple[dict[str, Any], float] | None:
        """Best label-matched case by word overlap, with its score."""
        content_words = set(_WORD_REGEX.findall(text.lower()))
        if not content_words:
            return None

        best_score = 0.0
        best_case: dict[str, Any] | None = None
        for case, words in zip(self.cases, self._word_sets):
            if exclude_id and case.get("id") == exclude_id:
                continue
            if not words:
                continue
            score = len(content_words & words) / len(words)
            if score > best_score:
                best_score = score
                best_case = case

        if best_case is None or best_score < 0.25:
            return None
        return best_case, round(best_score, 3)