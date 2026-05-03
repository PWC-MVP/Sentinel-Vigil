"""
Chat / Agentic AI router.
POST /api/chat          → send a message, stream SSE response
GET  /api/chat/status   → check LLM configuration status
"""
import json
import logging
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from backend.services.llm import stream_chat, get_llm_status, SYSTEM_PROMPT
from backend.services.tools import TOOLS, execute_tool

router = APIRouter(prefix="/api/chat", tags=["chat"])
logger = logging.getLogger(__name__)


class Message(BaseModel):
    role: str   # "user" | "assistant" | "tool"
    content: str


class ChatRequest(BaseModel):
    messages: list[Message]
    model: Optional[str] = None


@router.get("/status")
async def chat_status():
    """Check if an LLM is configured."""
    return get_llm_status()


@router.post("/upload")
async def upload_document(file: UploadFile = File(...)):
    """Extract text from an uploaded document (PDF or Text)."""
    import io
    from pypdf import PdfReader
    
    content_type = file.content_type
    filename = file.filename
    
    try:
        data = await file.read()
        if not data:
            return {"status": "error", "message": "File is empty"}
            
        if content_type == "application/pdf" or filename.endswith(".pdf"):
            # Process PDF
            try:
                reader = PdfReader(io.BytesIO(data), strict=False)
                text = ""
                for i, page in enumerate(reader.pages):
                    try:
                        page_text = page.extract_text()
                        if page_text:
                            text += f"--- Page {i+1} ---\n{page_text}\n\n"
                    except Exception as pe:
                        logger.warning(f"Failed to extract text from page {i}: {pe}")
                
                if not text.strip():
                    return {"status": "error", "message": "Could not extract any text from this PDF. It might be a scanned image or encrypted."}
            except Exception as re:
                logger.error(f"PdfReader init failed: {re}")
                return {"status": "error", "message": f"Malformed PDF: {str(re)}"}
            
            # Truncate if too large for single context block (limit ~60k chars)
            if len(text) > 60000:
                text = text[:60000] + "\n\n[TRUNCATED DUE TO SIZE]"
                
            return {"status": "success", "text": text, "pages": len(reader.pages)}
        else:
            # Assume text/log/kql
            text = data.decode("utf-8", errors="replace")
            if len(text) > 60000:
                text = text[:60000] + "\n\n[TRUNCATED DUE TO SIZE]"
            return {"status": "success", "text": text}
            
    except Exception as e:
        logger.error(f"Upload processing failed: {e}")
        return {"status": "error", "message": f"Failed to parse {filename}: {str(e)}"}


@router.post("")
async def chat(req: ChatRequest):
    """
    Agentic chat endpoint.
    Streams Server-Sent Events (text/event-stream).
    Handles multi-round tool calling automatically.
    """
    # Build message history with system prompt
    history = [{"role": "system", "content": SYSTEM_PROMPT}]
    for msg in req.messages:
        history.append({"role": msg.role, "content": msg.content})

    async def event_stream() -> AsyncGenerator[bytes, None]:
        async for chunk in stream_chat(history, TOOLS, execute_tool, model=req.model):
            yield chunk.encode("utf-8")

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
