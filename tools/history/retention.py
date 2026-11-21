"""D7 housekeeping for a dedicated local synthetic-history export directory."""
from __future__ import annotations

import argparse
import os
import re
import stat
import time
from pathlib import Path

RETENTION_SECONDS = 7 * 24 * 60 * 60
# Exporters choose the creation second once and keep it when a file is copied.
LOCAL_HISTORY = re.compile(r"rg-history-v1-([0-9]{1,12})-[0-9a-f]{32}\.bin(?:\.partial)?", re.ASCII)


def expire_local_exports(directory: Path, now_seconds: int) -> int:
    """Remove expired managed files. Caller owns and serializes this directory."""
    if now_seconds < 0:
        raise ValueError("negative UTC time")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(directory, flags)
    removed = 0
    try:
        with os.scandir(fd) as entries:
            for entry in entries:
                match = LOCAL_HISTORY.fullmatch(entry.name)
                if match is None or now_seconds - int(match[1]) < RETENTION_SECONDS:
                    continue
                if stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
                    os.unlink(entry.name, dir_fd=fd)
                    removed += 1
    finally:
        os.close(fd)
    return removed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="private local history directory")
    args = parser.parse_args()
    print(expire_local_exports(args.directory, int(time.time())))
