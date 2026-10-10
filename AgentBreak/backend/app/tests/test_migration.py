import sqlite3
import os
import pytest
from app.database.models import FindingModel
from app.database.connection import engine
from sqlalchemy.orm import Session
from migrate import migrate_database

def test_migration_status_to_execution_status(tmp_path):
    db_path = tmp_path / "test_migration.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create the old schema
    cursor.execute('''
        CREATE TABLE findings (
            id VARCHAR PRIMARY KEY,
            scan_id VARCHAR,
            test_id VARCHAR,
            category VARCHAR,
            status VARCHAR,
            outcome VARCHAR,
            expected_behavior VARCHAR,
            observed_behavior VARCHAR,
            evidence VARCHAR,
            trace_id VARCHAR,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert a record using the old schema
    cursor.execute('''
        INSERT INTO findings (id, scan_id, test_id, category, status, outcome) 
        VALUES ('find_123', 'scan_1', 'test_1', 'sec', 'running', 'failed')
    ''')
    conn.commit()
    conn.close()
    
    # Run migration
    migrate_database(str(db_path))
    
    # Verify migration
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info('findings')")
    columns = [col[1] for col in cursor.fetchall()]
    assert 'execution_status' in columns
    assert 'status' not in columns
    
    cursor.execute("SELECT id, execution_status FROM findings WHERE id='find_123'")
    record = cursor.fetchone()
    assert record is not None
    assert record[1] == 'running'
    conn.close()
