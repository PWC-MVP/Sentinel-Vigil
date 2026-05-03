"""
Reports router — browse and serve generated HTML reports.
"""
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, Response

from backend.config import settings

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _get_report_files() -> list[dict]:
    """Scan the reports directory tree for HTML files."""
    report_dir = settings.OUTPUT_DIR
    if not report_dir.exists():
        return []

    files = []
    for path in sorted(report_dir.rglob("*.html"), key=os.path.getmtime, reverse=True):
        try:
            stat = path.stat()
            files.append({
                "name": path.name,
                "relative_path": str(path.relative_to(report_dir)),
                "size_bytes": stat.st_size,
                "created": stat.st_mtime,
                "subdirectory": str(path.parent.relative_to(report_dir)) if path.parent != report_dir else "",
            })
        except Exception:
            pass
    return files


@router.get("")
async def list_reports():
    """List all generated investigation HTML reports."""
    return {"reports": _get_report_files(), "report_dir": str(settings.OUTPUT_DIR)}


@router.get("/{filename:path}")
async def get_report(filename: str):
    """Serve an HTML report file by name."""
    report_dir = settings.OUTPUT_DIR

    # Resolve and validate the path (prevent path traversal)
    target = (report_dir / filename).resolve()
    if not str(target).startswith(str(report_dir.resolve())):
        raise HTTPException(status_code=403, detail="Access denied")

    if not target.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    if target.suffix == ".html":
        content = target.read_text(encoding="utf-8")
        return HTMLResponse(content=content)

    return FileResponse(str(target))


@router.post("/export-pdf")
async def export_pdf(payload: dict):
    """Convert HTML content or existing file to PDF."""
    html_content = payload.get("html") or payload.get("html_content")
    filename = payload.get("filename", "export.pdf")
    file_path = payload.get("file_path")

    if not html_content and not file_path:
        raise HTTPException(status_code=400, detail="HTML content or file_path required")

    import os
    import tempfile
    from convert_html_to_pdf import html_to_pdf
    
    # Use system temp directory to avoid Uvicorn reloads during export
    temp_dir = Path(tempfile.gettempdir())
    
    if file_path:
        # Resolve existing file safely
        report_dir = settings.OUTPUT_DIR
        target = (report_dir / file_path).resolve()
        if not str(target).startswith(str(report_dir.resolve())):
            raise HTTPException(status_code=403, detail="Access denied")
        if not target.exists():
            raise HTTPException(status_code=404, detail="File not found")
        source_html = target
    else:
        # Create a temp HTML file
        temp_fd, temp_h_path = tempfile.mkstemp(suffix=".html", prefix="export_")
        os.close(temp_fd)
        source_html = Path(temp_h_path)
        source_html.write_text(html_content, encoding="utf-8")

    # Create a temp PDF path
    temp_fd, temp_p_path = tempfile.mkstemp(suffix=".pdf", prefix="export_")
    os.close(temp_fd)
    out_pdf = Path(temp_p_path)
    
    temp_html_created = not file_path  # only delete if we created it
    try:
        html_to_pdf(str(source_html), str(out_pdf))
        if not out_pdf.exists() or out_pdf.stat().st_size == 0:
            raise Exception("PDF file is empty or missing after conversion")

        pdf_bytes = out_pdf.read_bytes()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF conversion failed: {str(e)}")
    finally:
        if temp_html_created:
            try: source_html.unlink(missing_ok=True)
            except Exception: pass
        try: out_pdf.unlink(missing_ok=True)
        except Exception: pass
@router.post("/export-html")
async def export_html(payload: dict):
    """Serve raw HTML content or an existing report file as a downloadable file."""
    html_content = payload.get("html") or payload.get("html_content")
    filename = payload.get("filename", "export.html")
    file_path = payload.get("file_path")
    
    if not html_content and not file_path:
        raise HTTPException(status_code=400, detail="HTML content or file_path required")
        
    if file_path:
        # Resolve existing file safely
        report_dir = settings.OUTPUT_DIR
        target = (report_dir / file_path).resolve()
        if not str(target).startswith(str(report_dir.resolve())):
            raise HTTPException(status_code=403, detail="Access denied")
        if not target.exists():
            raise HTTPException(status_code=404, detail="File not found")
        content = target.read_text(encoding="utf-8")
    else:
        content = html_content

    return HTMLResponse(
        content=content,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
