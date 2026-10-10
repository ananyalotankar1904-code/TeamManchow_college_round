from fastapi import APIRouter

router = APIRouter()

@router.get("/{scan_id}/export")
def export_report(scan_id: str):
    return {"message": "Export functionality not yet implemented", "scan_id": scan_id}
