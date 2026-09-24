"""Third-party notices for a release archive: THIRD_PARTY.json and licenses/<crate>/<file>.

Usage: python scripts/third_party.py <cargo metadata JSON> <archive folder>
The metadata must come from `cargo metadata --locked --format-version 1 --filter-platform <target>`,
so only the crates resolved for that target and the default features are listed.
"""
import json
import re
import sys
from pathlib import Path

metadata = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
dest = Path(sys.argv[2])
used = {node["id"] for node in metadata["resolve"]["nodes"]}
inventory = []
for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
    if package["source"] is None or package["id"] not in used:
        continue  # this repository's own crates, or crates not built for this target
    name = f"{package['name']}-{package['version']}"
    assert re.fullmatch(r"[A-Za-z0-9_.+-]+", name), name
    directory = Path(package["manifest_path"]).parent.resolve()
    found = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if not path.name.lower().startswith(("license", "licence", "copying", "copyright", "notice", "authors")):
            continue
        if path.suffix.lower() not in ("", ".txt", ".md", ".rst"):
            continue
        data = path.read_bytes()
        if len(data) > 262144 or b"\0" in data:
            continue
        relative = path.relative_to(directory).as_posix()
        target = dest / "licenses" / name / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        found.append(relative)
    inventory.append({
        "name": package["name"], "version": package["version"], "declared_license": package.get("license"),
        "source": f"https://crates.io/crates/{package['name']}/{package['version']}", "included_notices": found,
    })
missing = [p["name"] for p in inventory if not (p["declared_license"] or p["included_notices"])]
assert not missing, f"no license information for: {missing}"
(dest / "THIRD_PARTY.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
print(f"{len(inventory)} third-party crates")
