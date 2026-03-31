import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from dive.dns import (
    DiveRecordInvalid,
    DiveRecordNotFound,
    get_dive_record,
    get_dive_record_walk,
    get_key_record,
    get_key_record_walk,
)

# ── Config ────────────────────────────────────────────────────────────────────

TEST_FQDN = "callec.net"
TEST_KEY_ID = "mykey"
DNS_SERVER = "1.1.1.1"

# ── Helpers ───────────────────────────────────────────────────────────────────


def section(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def try_call(fn, *args):
    try:
        result = fn(*args, custom_dns=DNS_SERVER)
        for item in result:
            for k, v in item.items():
                print(f"  {k:<20} {v}")
            print()
    except DiveRecordNotFound as e:
        print(f"  [NOT FOUND] {e}")
    except DiveRecordInvalid as e:
        print(f"  [INVALID]   {e}")
    except Exception as e:
        print(f"  [ERROR]     {type(e).__name__}: {e}")


# ── Tests ─────────────────────────────────────────────────────────────────────

section(f"get_dive_record({TEST_FQDN!r}) via {DNS_SERVER}")
try_call(get_dive_record, TEST_FQDN)

section(f"get_dive_record_walk({TEST_FQDN!r}) via {DNS_SERVER}")
try_call(get_dive_record_walk, TEST_FQDN)

section(f"get_key_record({TEST_FQDN!r}, {TEST_KEY_ID!r}) via {DNS_SERVER}")
try_call(get_key_record, TEST_FQDN, TEST_KEY_ID)

section(f"get_key_record_walk({TEST_FQDN!r}, {TEST_KEY_ID!r}) via {DNS_SERVER}")
try_call(get_key_record_walk, TEST_FQDN, TEST_KEY_ID)
