from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

BINARY_EXTS = {".bin", ".png", ".jpg", ".jpeg", ".ico", ".wasm", ".pyc"}


def test_no_unexpected_control_characters_in_tracked_files():
    """Verify that no tracked text or documentation files contain NUL bytes or rogue control characters."""
    res = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    tracked_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]

    corrupted = []

    for file_str in tracked_files:
        p = ROOT / file_str
        if not p.is_file():
            continue
        if p.suffix.lower() in BINARY_EXTS:
            continue

        raw = p.read_bytes()
        if b"\x00" in raw:
            corrupted.append(f"{file_str}: contains NUL byte (\\x00)")
            continue

        bad_controls = []
        for idx, b in enumerate(raw):
            if b < 32 and b not in (9, 10, 13):
                bad_controls.append((idx, hex(b)))

        if bad_controls:
            corrupted.append(f"{file_str}: contains {len(bad_controls)} control characters: {bad_controls[:5]}")

    assert not corrupted, "Control character corruption found in tracked files:\n" + "\n".join(corrupted)
