import sqlite3
import os

def migrate_database(db_path: str):
    if not os.path.exists(db_path):
        print(f"Database {db_path} does not exist. Skipping migration.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Check if findings table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        if not cursor.fetchone():
            print("Table 'findings' does not exist. Skipping.")
            return

        # Check columns in findings
        cursor.execute("PRAGMA table_info('findings')")
        columns = [col[1] for col in cursor.fetchall()]

        if 'status' in columns and 'execution_status' not in columns:
            print("Migrating 'findings' table: renaming 'status' to 'execution_status'.")
            cursor.execute("BEGIN TRANSACTION")
            cursor.execute("ALTER TABLE findings RENAME COLUMN status TO execution_status")
            conn.commit()
            print("Migration successful.")
        else:
            print("Migration not needed or already applied.")
            
    except Exception as e:
        conn.rollback()
        print(f"Migration failed: {e}")
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database("agentbreak.db")
