"""
ransomware_simulator.py — SAFE ransomware behavior simulator for demos.

=====================================================================
  WARNING  WARNING  WARNING  WARNING  WARNING  WARNING  WARNING
=====================================================================

  This script simulates ransomware-like behavior for EDUCATIONAL and
  DEMONSTRATION purposes ONLY.

  HARD SAFETY RULES:
    1. It ONLY operates inside the sandboxed test_folder/ directory
       inside this project. It hard-refuses to run if that path check fails.
    2. It NEVER touches real user data, system files, or anything
       outside test_folder/.
    3. The "encryption" is a trivial XOR with a fixed key — files are
       trivially recoverable (the original bytes are XORed back).
    4. Do NOT rename the folder, move this script, or point it at
       other directories.

  RUN ONLY INSIDE THE PROJECT'S test_folder/ SANDBOX.
=====================================================================

Behavior simulated (mimics real ransomware TTPs):
  1. Create a batch of dummy "victim" files (documents/images/db).
  2. Rapidly "encrypt" them (XOR) — file entropy rises sharply.
  3. Rename each file to .locked (mass extension change).
  4. Drop a ransom note (README_RECOVER.txt).

The detector running on test_folder/ must flag this as RANSOMWARE.
"""

from __future__ import annotations

import sys
import time
import os
from pathlib import Path

# ------------------------------------------------------------------
# SAFETY: hard-coded sandbox path. Refuse anything else.
# ------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SANDBOX = (PROJECT_ROOT / "test_folder").resolve()

XOR_KEY = 0x5A  # legacy constant, kept for reference (see DEMO_KEY keystream below)
RANSOM_NOTE_NAME = "README_RECOVER.txt"
RANSOM_NOTE_BODY = """\
================================================================
  YOUR FILES HAVE BEEN "ENCRYPTED"
================================================================

This is a SIMULATED ransomware note for an academic demonstration.

Your files have been renamed to .locked and "encrypted" with a
demo stream cipher (SHA-256 keystream XOR). This is NOT real
ransomware encryption.

To recover (in this simulation):
    * Run: python ransomware_simulator.py --recover
    * Every .locked file is decrypted and renamed back.

This simulator ONLY ran inside the sandbox folder:
    {sandbox}

================================================================
"""

FILE_CONTENTS = {
    ".doc": "Quarterly report {i}. Confidential internal document. " * 40,
    ".txt": "Meeting notes {i}:\n- Discuss project timeline\n- Review budget\n" * 30,
    ".csv": "id,name,value,status\n" + "".join(f"{j},item{j},{j*13},ok\n" for j in range(200)),
    ".jpg": None,  # random bytes
    ".png": None,
    ".db": None,   # random bytes
    ".pdf": "PDF-FAKE-{i} " * 500,
}

EXTENSIONS = list(FILE_CONTENTS.keys())


# ------------------------------------------------------------------
# Demo stream cipher: SHA-256 counter-mode keystream.
# XOR with a SINGLE fixed byte would PRESERVE Shannon entropy exactly
# (bijective substitution). Real ransomware uses real ciphers (AES etc.)
# that produce near-random output (entropy ~8.0). This keystream is
# deterministic + high-entropy: applying it raises file entropy to ~8.0
# AND applying it twice restores the original bytes (reversible demo).
# ------------------------------------------------------------------
DEMO_KEY = b"RANSOMWARE-DEMO-XOR-KEY-v1"


def _keystream(length: int) -> bytes:
    """Deterministic high-entropy keystream (SHA-256 in counter mode)."""
    import hashlib

    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(DEMO_KEY + counter.to_bytes(8, "little")).digest())
        counter += 1
    return bytes(out[:length])


def _xor_crypt(data: bytes) -> bytes:
    """XOR data with keystream. Self-inverse: call twice to restore."""
    ks = _keystream(len(data))
    return bytes(d ^ k for d, k in zip(data, ks))


def safety_check(target: Path) -> bool:
    """Verify target resolves INSIDE the sandbox. Refuse otherwise."""
    target = target.resolve()
    try:
        target.relative_to(SANDBOX)
        return True
    except ValueError:
        return False


def create_victim_files(sandbox: Path, num_files: int, delay: float) -> list[Path]:
    """Create dummy files of varied types inside the sandbox."""
    created = []
    for i in range(num_files):
        ext = EXTENSIONS[i % len(EXTENSIONS)]
        path = sandbox / f"victim_document_{i:03d}{ext}"
        content = FILE_CONTENTS[ext]
        if content is None:
            # Binary-looking content (moderate entropy before "encryption")
            path.write_bytes(os.urandom(4096) + b"\x00" * 2048)
        else:
            path.write_text(content.format(i=i), encoding="utf-8")
        created.append(path)
        print(f"  [create] {path.name}")
        time.sleep(delay)
    return created


def xor_encrypt(path: Path, delay: float) -> None:
    """'Encrypt' with demo keystream — raises file entropy to ~8.0 (reversible)."""
    data = path.read_bytes()
    encrypted = _xor_crypt(data)
    path.write_bytes(encrypted)
    print(f"  [encrypt] {path.name}  entropy up")
    time.sleep(delay)


def rename_locked(path: Path, delay: float) -> Path:
    """Rename file to .locked (mass extension change pattern)."""
    new_path = path.with_suffix(path.suffix + ".locked")
    path.replace(new_path)  # overwrite stale target from a previous run
    print(f"  [rename]  {path.name} -> {new_path.name}")
    time.sleep(delay)
    return new_path


def drop_ransom_note(sandbox: Path) -> None:
    note = sandbox / RANSOM_NOTE_NAME
    note.write_text(RANSOM_NOTE_BODY.format(sandbox=sandbox), encoding="utf-8")
    print(f"  [note]    {RANSOM_NOTE_NAME} dropped")


def recover_all(sandbox: Path) -> int:
    """Undo the simulation: XOR keystream back and restore original names."""
    recovered = 0
    for p in sorted(sandbox.glob("*.locked")):
        data = p.read_bytes()
        original = _xor_crypt(data)
        # Remove the .locked suffix
        orig_name = p.name[: -len(".locked")]
        orig_path = p.parent / orig_name
        orig_path.write_bytes(original)
        p.unlink()
        recovered += 1
    # Remove ransom note
    note = sandbox / RANSOM_NOTE_NAME
    if note.exists():
        note.unlink()
    return recovered


def run(num_files: int = 30, delay: float = 0.05) -> None:
    """
    Execute the simulated attack inside the sandbox.
    Refuses to run if sandbox check fails.
    """
    print("=" * 64)
    print("  RANSOMWARE SIMULATOR — EDUCATIONAL USE ONLY")
    print("  This runs ONLY inside test_folder/ (hard sandbox).")
    print("=" * 64)

    sandbox = SANDBOX

    # ---- HARD SAFETY CHECK ----
    if not safety_check(sandbox):
        print(f"[FATAL] Sandbox safety check FAILED for {sandbox}.")
        print("[FATAL] Refusing to run.")
        sys.exit(1)
    if not sandbox.exists():
        print(f"[FATAL] Sandbox does not exist: {sandbox}")
        sys.exit(1)

    # Extra guard: never allow user override from CLI
    print(f"[sandbox] {sandbox}")
    print(f"[sandbox] Safety check PASSED (path is inside project test_folder/)")
    print(f"[plan]    1. create {num_files} dummy victim files")
    print(f"[plan]    2. XOR-encrypt each (entropy spike)")
    print(f"[plan]    3. rename each to .locked (mass extension change)")
    print(f"[plan]    4. drop {RANSOM_NOTE_NAME}\n")

    t0 = time.time()

    print("--- Phase 1: create victim files ---")
    files = create_victim_files(sandbox, num_files, delay)

    print("\n--- Phase 2: encrypt (XOR, reversible) ---")
    for f in files:
        if f.exists():
            xor_encrypt(f, delay)

    print("\n--- Phase 3: mass rename to .locked ---")
    for f in files:
        if f.exists():
            rename_locked(f, delay)

    print("\n--- Phase 4: ransom note ---")
    drop_ransom_note(sandbox)

    elapsed = time.time() - t0
    print(f"\n[simulate] DONE in {elapsed:.1f}s — {num_files} files processed.")
    print("[simulate] The detector should have flagged this activity.")
    print("[simulate] To restore files (undo simulation), run:")
    print(f"           python \"{__file__}\" --recover")


def recover() -> None:
    """Restore all .locked files in the sandbox."""
    sandbox = SANDBOX
    if not safety_check(sandbox):
        print("[FATAL] Sandbox safety check FAILED. Refusing.")
        sys.exit(1)
    n = recover_all(sandbox)
    print(f"[recover] Restored {n} file(s) in {sandbox}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="SAFE ransomware simulator (test_folder/ ONLY)"
    )
    parser.add_argument("--files", type=int, default=30)
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--recover", action="store_true",
                        help="Undo the simulation (restore files)")
    args = parser.parse_args()

    if args.recover:
        recover()
    else:
        run(num_files=args.files, delay=args.delay)