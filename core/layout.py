from __future__ import annotations

from collections.abc import Sequence

MIB = 1024 * 1024
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
PAYLOAD_HEADER_LEN = 48
# salt + nonce + tag + PAYL header — minimum bytes before any ZIP payload fits
MIN_SLOT_BYTES = SALT_LEN + NONCE_LEN + TAG_LEN + PAYLOAD_HEADER_LEN

DEFAULT_SLOT_COUNT = 4


def equal_layout(region_size: int, slot_count: int) -> tuple[int, ...]:
    if slot_count < 2:
        raise ValueError("slot_count must be at least 2")
    if region_size <= 0:
        raise ValueError("Container size must be greater than 0")
    if region_size % slot_count != 0:
        raise ValueError("Container size must be divisible by slot count")
    slot_size = region_size // slot_count
    validate_slot_size(slot_size)
    return tuple(slot_size for _ in range(slot_count))


def validate_slot_size(slot_size: int) -> None:
    if slot_size <= MIN_SLOT_BYTES:
        raise ValueError("Slot size is too small")


def normalize_layout(layout: Sequence[int], *, expected_total: int | None = None) -> tuple[int, ...]:
    if len(layout) < 2:
        raise ValueError("layout must contain at least 2 slots")
    sizes = tuple(int(size) for size in layout)
    if any(size <= 0 for size in sizes):
        raise ValueError("Each slot size must be greater than 0")
    for size in sizes:
        validate_slot_size(size)
    total = sum(sizes)
    if expected_total is not None and total != expected_total:
        raise ValueError("Layout sizes must sum to the container slot region size")
    return sizes


def resolve_layout(
    region_size: int,
    *,
    layout: Sequence[int] | None = None,
    slot_count: int | None = None,
) -> tuple[int, ...]:
    if layout is not None and slot_count is not None:
        raise ValueError("Provide either layout or slot_count, not both")
    if layout is not None:
        return normalize_layout(layout, expected_total=region_size)
    count = DEFAULT_SLOT_COUNT if slot_count is None else slot_count
    return equal_layout(region_size, count)


def slot_offset(layout: Sequence[int], slot_index: int) -> int:
    if not 0 <= slot_index < len(layout):
        raise ValueError("slot_index out of range")
    return sum(layout[:slot_index])


def zip_capacity_for_slot(slot_size: int) -> int:
    """Maximum ZIP payload bytes that fit in a slot."""
    return max(0, slot_size - MIN_SLOT_BYTES)


def parse_slot_sizes_mib(raw: str) -> tuple[int, ...]:
    parts = [part.strip() for part in raw.replace(";", ",").split(",") if part.strip()]
    if len(parts) < 2:
        raise ValueError("slot sizes must list at least two MiB values")
    sizes_mib: list[int] = []
    for part in parts:
        try:
            value = int(part)
        except ValueError as exc:
            raise ValueError(f"Invalid slot size: {part}") from exc
        if value <= 0:
            raise ValueError("Each slot size must be greater than 0")
        sizes_mib.append(value)
    return tuple(size * MIB for size in sizes_mib)


def format_slot_sizes_mib(layout: Sequence[int]) -> str:
    if any(size % MIB != 0 for size in layout):
        return ",".join(str(size) for size in layout)
    return ",".join(str(size // MIB) for size in layout)
