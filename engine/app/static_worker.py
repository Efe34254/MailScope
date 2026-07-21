from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print(json.dumps({"error": "Expected attachment path and detected type"}))
        return 2
    from .static_tools import scan_attachment_direct

    path = Path(sys.argv[1]).resolve()
    if not path.is_file():
        print(json.dumps({"error": "Attachment file was not found"}))
        return 3
    result = scan_attachment_direct(path, sys.argv[2])
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
