from app.database.connection import SessionLocal, Base, engine
from app.database.models import AgentModel

def test_db_connection():
    # Create tables
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    # Simple query to ensure connection and tables work
    result = db.query(AgentModel).all()
    assert isinstance(result, list)
    db.close()
