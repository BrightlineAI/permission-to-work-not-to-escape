from __future__ import annotations


def intersect_authority(parent: set[str], requested: set[str], policy: set[str]) -> set[str]:
    """A delegate can receive only authority present in all three sets."""
    return parent & requested & policy


def expands_authority(parent: set[str], child: set[str]) -> bool:
    return not child <= parent
