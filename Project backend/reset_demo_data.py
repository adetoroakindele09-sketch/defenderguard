import sqlite3
from pathlib import Path

DB = Path(__file__).with_name("database.db")
conn = sqlite3.connect(DB)
for table in ("scan_history", "activity_logs", "reports"):
    conn.execute(f"DELETE FROM {table}")
conn.commit()
conn.close()
print("Old scan/activity/report records cleared. Users and settings were preserved.")
