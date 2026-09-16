# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""The identifier shared by scan sessions and batch runs.

One shape serves both ``tacs scan`` session directories and ``tacs repos``
batch run directories::

    20260916T151300Z_7c91ab

The UTC timestamp keeps the id readable and sorts directory listings
chronologically; the random suffix makes two runs started in the same second
distinct. Uniqueness comes from the randomness alone, so nothing has to inspect
the filesystem or coordinate with other processes to mint an id.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

# Second-resolution UTC stamp followed by six hex characters.
RUN_ID_PATTERN = re.compile(r"^\d{8}T\d{6}Z_[0-9a-f]{6}$")

# Enough randomness that same-second collisions stay negligible at the scale of
# runs a user or CI job actually starts, while keeping directory names short.
_SUFFIX_HEX_CHARS = 6


def new_run_id() -> str:
    """Mint a fresh run/session id of the form ``YYYYMMDDTHHMMSSZ_<6-hex>``."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}_{uuid.uuid4().hex[:_SUFFIX_HEX_CHARS]}"
