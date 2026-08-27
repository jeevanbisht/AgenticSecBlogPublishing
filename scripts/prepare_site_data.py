"""Validate and copy the committed public bundle into Astro's generated data path."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentic_security.publishing.validation import validate_publication_bundle  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bundle",
        type=Path,
        default=Path(os.environ.get("ASI_EXPORT_PATH", ROOT / "publication")),
    )
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    manifest = validate_publication_bundle(bundle)
    output = ROOT / "site" / "src" / "data" / "ledger.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(bundle / "data" / "ledger.json", output)
    print(f"Prepared {output} from {len(manifest.files)} validated public file(s)")
