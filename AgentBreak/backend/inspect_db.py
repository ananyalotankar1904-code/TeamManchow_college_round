import sqlite3

def inspect(db_path):
    print(f"--- DB: {db_path} ---")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    tables = [row[0] for row in cursor.fetchall()]

    schema_info = {}
    for table in tables:
        cursor.execute(f"PRAGMA table_info('{table}');")
        columns = cursor.fetchall()
        schema_info[table] = columns

    for table, cols in schema_info.items():
        print(f"Table: {table}")
        for col in cols:
            print(f"  {col}")

inspect('agentbreak.db')
print("\n")
inspect('test.db')
