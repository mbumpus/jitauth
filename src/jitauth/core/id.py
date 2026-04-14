"""ID generation for JITAuth entities."""

from ulid import ULID


def new_id() -> str:
    """Generate a new ULID string."""
    return str(ULID())
