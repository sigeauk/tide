"""
Pre-migration backup script for multi-tenant transition.
Run via: docker exec tide-app python /app/app/scripts/backup_pre_multitenant.py

Creates a timestamped backup of tide.duckdb before Migration v25.
"""

import os
import shutil
import sys
import duckdb

DB_PATH = os.environ.get("DB_PATH", "/app/data/tide.duckdb")
BACKUP_PATH = DB_PATH + ".pre-multitenant.bak"


def main():
    if not os.path.exists(DB_PATH):
        print(f"ERROR: Database not found at {DB_PATH}")
        sys.exit(1)

    print(f"Source:  {DB_PATH} ({os.path.getsize(DB_PATH):,} bytes)")

    # Copy the file
    shutil.copy2(DB_PATH, BACKUP_PATH)
    print(f"Backup:  {BACKUP_PATH} ({os.path.getsize(BACKUP_PATH):,} bytes)")

    # Verify backup integrity with read-only open
    try:
        conn = duckdb.connect(BACKUP_PATH, read_only=True)
        version = conn.execute(
            "SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1"
        ).fetchone()
        table_count = conn.execute(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'main'"
        ).fetchone()
        conn.close()
        print(f"Verified: schema v{version[0]}, {table_count[0]} tables")
        print("Backup OK — safe to proceed with migration.")
    except Exception as e:
        print(f"ERROR: Backup verification failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
