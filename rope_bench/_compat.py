"""Compatibility helpers for supported Python runtimes."""

from __future__ import annotations

from itertools import zip_longest
from typing import Iterable, Iterator, TypeVar

T = TypeVar("T")
_MISSING = object()


def strict_zip(*iterables: Iterable[T]) -> Iterator[tuple[T, ...]]:
    """Backport zip(..., strict=True) for Python 3.9."""

    for values in zip_longest(*iterables, fillvalue=_MISSING):
        if any(value is _MISSING for value in values):
            raise ValueError("zip() argument lengths differ")
        yield values  # type: ignore[misc]
