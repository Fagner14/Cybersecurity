from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BruteForceResult:
    found: bool
    password: str | None
    attempts: int
    elapsed_seconds: float


def hash_password(password: str, salt: str = "cyberlab") -> str:
    payload = f"{salt}:{password}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_wordlist(path: str | Path) -> list[str]:
    wordlist_path = Path(path)
    if not wordlist_path.exists():
        raise ValueError(f"Wordlist nao encontrada: {wordlist_path}")

    words: list[str] = []
    with wordlist_path.open("r", encoding="utf-8") as file:
        for line in file:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
    return words


def run_dictionary_attack(password: str, wordlist_path: str | Path, salt: str = "cyberlab") -> BruteForceResult:
    target_hash = hash_password(password, salt)
    words = load_wordlist(wordlist_path)
    started_at = time.perf_counter()

    for attempt, candidate in enumerate(words, start=1):
        if hash_password(candidate, salt) == target_hash:
            return BruteForceResult(
                found=True,
                password=candidate,
                attempts=attempt,
                elapsed_seconds=time.perf_counter() - started_at,
            )

    return BruteForceResult(
        found=False,
        password=None,
        attempts=len(words),
        elapsed_seconds=time.perf_counter() - started_at,
    )
