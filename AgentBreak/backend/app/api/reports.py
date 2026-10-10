from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.services.report_builder import build_report
from app.services.report_service import generate_json_report, generate_pdf_report

router = APIRouter()

@router.get("/{scan_id}/export")
def export_report(
    scan_id: str, 
    format: str = Query("json", description="Export format: json or pdf"),
    db: Session = Depends(get_db)
):
    try:
        report = build_report(db, scan_id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to build report data") from e

    format_lower = format.lower()
    if format_lower == "json":
        try:
            json_str = generate_json_report(report)
            return Response(content=json_str, media_type="application/json")
        except Exception as e:
            raise HTTPException(status_code=500, detail="Failed to generate JSON report") from e
    elif format_lower == "pdf":
        try:
            pdf_bytes = generate_pdf_report(report)
            headers = {
                "Content-Disposition": f'attachment; filename="report_{scan_id}.pdf"'
            }
            return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)
        except Exception as e:
            raise HTTPException(status_code=500, detail="Failed to generate PDF report") from e
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'json' or 'pdf'.")
