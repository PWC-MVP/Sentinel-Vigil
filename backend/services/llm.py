"""
LLM client — supports Azure Anthropic (Claude) natively.
"""
import os
import json
import logging
import httpx
from typing import AsyncGenerator

logger = logging.getLogger(__name__)


def _llm_creds() -> dict:
    """Read LLM credentials fresh from os.environ on every call so .env changes apply immediately."""
    return {
        "anthropic_key":       (os.getenv("AZURE_ANTHROPIC_API_KEY") or "").strip(),
        "anthropic_endpoint":  (os.getenv("AZURE_ANTHROPIC_ENDPOINT") or "").strip(),
        "anthropic_model":     os.getenv("AZURE_ANTHROPIC_MODEL", "claude-sonnet-4-6"),
        "anthropic_max_tokens": int(os.getenv("AZURE_ANTHROPIC_MAX_TOKENS", "8192")),
        "azure_endpoint":     (os.getenv("AZURE_OPENAI_ENDPOINT") or "").strip(),
        "azure_key":          (os.getenv("AZURE_OPENAI_API_KEY") or "").strip(),
        "azure_deploy":       os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
        "azure_version":      os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"),
        "openai_key":         (os.getenv("OPENAI_API_KEY") or "").strip(),
        "openai_model":       os.getenv("OPENAI_MODEL", "gpt-4o"),
    }

SYSTEM_PROMPT = """You are ARIA (Advanced Risk Intelligence Assistant), a elite Tier-3 Cyber Security Analyst built for the PwC Sentinel Engineering Team.

Your goal is to provide deep, actionable insights into security telemetry from Microsoft Sentinel and Microsoft Graph.

## Your Capabilities
- **User Investigation**: Deep analysis of sign-ins, anomalies, MFA, devices, and Risk Detections.
- **KQL Query Execution**: Real-time Kusto query execution against Log Analytics.
- **Threat Intelligence**: Multi-source IP enrichment (Geo, VPN, AbuseIPDB, Shodan).
- **Security Posture**: Analysis of app registrations and tenant security settings.
- **Document Analysis**: You can read and analyze uploaded security logs, PDF reports, and exported configurations provided in the conversation context.

## Rules
1. **Evidence-based only**: Never fabricate data. Use exact tool results.
2. **Professional & Structured**: Avoid fluff. Use headings, bold text, and horizontal rules (`---`).
3. **Always use tables**: When presenting multi-field data (e.g., enrichment results, incident lists, sign-in details), **USE MARKDOWN TABLES**.
4. **Emoji Support**: Use relevant emojis to highlight status (✅ 🛡️ ⚠️ 🔴 🔍).
5. **Clear Risk Assessment**: Every investigation must start with a clear Risk Level.
6. **Context Awareness**: If a document (PDF or Text) is provided at the start of a message, analyze its contents thoroughly to answer the user's specific questions about that file.

## Response Format
- **Executive Summary**: 2-3 sentences max.
- **Findings Table**: Detailed attributes in a clean markdown table.
- **Detailed Analysis**: Bulleted list of key observations.
- **Recommended Actions**: Ranked by priority.
- **KQL Reference**: (Optional) Show the query used if relevant.

### Example Table Format
| Attribute | Detail | Status |
| :--- | :--- | :--- |
| **Location** | London, GB | ✅ Expected |
| **IP Address** | 1.2.3.4 | 🔴 High Abuse Score (98%) |
| **VPN/Proxy** | Detected | ⚠️ Masking identity |
"""

# ── Status and Routing ────────────────────────────────────────────────────────

def get_llm_status() -> dict:
    c = _llm_creds()
    if c["anthropic_key"] and c["anthropic_endpoint"]:
        return {"available": True, "provider": "Azure Anthropic", "model": c["anthropic_model"]}
    if c["azure_key"] and c["azure_endpoint"]:
        return {"available": True, "provider": "Azure OpenAI", "model": c["azure_deploy"]}
    if c["openai_key"]:
        return {"available": True, "provider": "OpenAI", "model": c["openai_model"]}
    return {"available": False, "hint": "Configure LLM credentials in .env file."}


async def stream_chat(
    messages: list[dict],
    tools: list[dict],
    on_tool_call,
    model: str | None = None,
) -> AsyncGenerator[str, None]:
    """Route chat stream to correct provider."""
    c = _llm_creds()
    if c["anthropic_key"] and c["anthropic_endpoint"]:
        async for chunk in _stream_anthropic_raw(messages, tools, on_tool_call, model=model):
            yield chunk
    elif c["azure_key"] or c["openai_key"]:
        async for chunk in _stream_openai(messages, tools, on_tool_call):
            yield chunk
    else:
        yield 'data: {"type":"error","content":"No LLM configured in .env"}\n\n'


# ── Raw Azure Anthropic Implementation ────────────────────────────────────────

async def _stream_anthropic_raw(messages, tools, on_tool_call, model: str | None = None) -> AsyncGenerator[str, None]:
    """
    Directly hits the provided Azure Anthropic endpoint using httpx.
    """
    c = _llm_creds()
    anthropic_key      = c["anthropic_key"]
    anthropic_endpoint = c["anthropic_endpoint"]
    anthropic_model    = model or c["anthropic_model"]

    # Filter history
    history = []
    for m in messages:
        if m["role"] in ["user", "assistant"]:
            history.append({"role": m["role"], "content": m["content"]})

    anthropic_tools = []
    for t in tools:
        if "function" in t:
            anthropic_tools.append({
                "name": t["function"]["name"],
                "description": t["function"].get("description", ""),
                "input_schema": t["function"]["parameters"]
            })

    MAX_ROUNDS = 8
    for round_num in range(MAX_ROUNDS):
        payload = {
            "model": anthropic_model,
            "messages": history,
            "system": SYSTEM_PROMPT,
            "max_tokens": 4096,
            "stream": True,
            "tools": anthropic_tools if anthropic_tools else None
        }

        headers = {
            "Authorization": f"Bearer {anthropic_key}",
            "api-key": anthropic_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }

        try:
            async with httpx.AsyncClient() as client:
                url = anthropic_endpoint
                if "api-version" not in url:
                    url += "?api-version=2024-10-31-preview"

                async with client.stream("POST", url, json=payload, headers=headers, timeout=60.0) as response:
                    if response.status_code != 200:
                        err_text = await response.aread()
                        yield f'data: {json.dumps({"type":"error","content":f"Anthropic HTTP {response.status_code}: {err_text.decode()}" })}\n\n'
                        return

                    full_content = ""
                    tool_calls_accumulator = {}

                    async for line in response.aiter_lines():
                        if not line.startswith("data: "): continue
                        data_str = line[6:].strip()
                        if data_str == "[DONE]": break
                        
                        try:
                            event = json.loads(data_str)
                        except:
                            continue

                        e_type = event.get("type")
                        if e_type == "content_block_start" and event["content_block"]["type"] == "tool_use":
                            idx = event["index"]
                            tool_calls_accumulator[idx] = {
                                "id": event["content_block"]["id"],
                                "name": event["content_block"]["name"],
                                "args": ""
                            }
                        elif e_type == "content_block_delta":
                            delta = event["delta"]
                            if delta["type"] == "text_delta":
                                text = delta["text"]
                                full_content += text
                                yield f'data: {json.dumps({"type":"delta","content":text})}\n\n'
                            elif delta["type"] == "input_json_delta":
                                idx = event["index"]
                                if idx in tool_calls_accumulator:
                                    tool_calls_accumulator[idx]["args"] += delta["partial_json"]

            if not tool_calls_accumulator:
                yield f'data: {json.dumps({"type":"done"})}\n\n'
                return

            blocks = []
            if full_content:
                blocks.append({"type": "text", "text": full_content})
            for tc in tool_calls_accumulator.values():
                try: args_dict = json.loads(tc["args"])
                except: args_dict = {}
                blocks.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": args_dict})
            history.append({"role": "assistant", "content": blocks})

            tool_results_blocks = []
            for tc in tool_calls_accumulator.values():
                name = tc["name"]
                try: args_dict = json.loads(tc["args"])
                except: args_dict = {}
                yield f'data: {json.dumps({"type":"tool_call","name":name,"args":args_dict})}\n\n'
                try:
                    result = await on_tool_call(name, args_dict)
                except Exception as e:
                    result = f"ERROR: {e}"
                yield f'data: {json.dumps({"type":"tool_result","name":name,"result":str(result)[:2000]})}\n\n'
                tool_results_blocks.append({"type": "tool_result", "tool_use_id": tc["id"], "content": str(result)[:6000]})
            history.append({"role": "user", "content": tool_results_blocks})

        except Exception as e:
            yield f'data: {json.dumps({"type":"error","content":f"Stream Connection Error: {str(e)}" })}\n\n'
            return

    yield f'data: {json.dumps({"type":"error","content":"Max tool call rounds reached."})}\n\n'


# ── OpenAI / Azure OpenAI ─────────────────────────────────────────────────────

async def _stream_openai(messages, tools, on_tool_call) -> AsyncGenerator[str, None]:
    from openai import AsyncAzureOpenAI, AsyncOpenAI
    c = _llm_creds()
    if c["azure_endpoint"] and c["azure_key"]:
        client = AsyncAzureOpenAI(azure_endpoint=c["azure_endpoint"], api_key=c["azure_key"], api_version=c["azure_version"])
        model = c["azure_deploy"]
    else:
        client = AsyncOpenAI(api_key=c["openai_key"])
        model = c["openai_model"]
    history = list(messages)
    MAX_ROUNDS = 8
    for round_num in range(MAX_ROUNDS):
        try:
            stream = await client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": SYSTEM_PROMPT}] + history,
                tools=tools if tools else None,
                tool_choice="auto" if tools else None,
                stream=True,
                temperature=0.1,
            )
        except Exception as e:
            yield f'data: {json.dumps({"type":"error","content":str(e)})}\n\n'
            return
        full_content, tool_calls_accumulator, finish_reason = "", {}, None
        async for chunk in stream:
            choice = chunk.choices[0] if chunk.choices else None
            if not choice: continue
            delta, finish_reason = choice.delta, choice.finish_reason
            if delta.content:
                full_content += delta.content
                yield f'data: {json.dumps({"type":"delta","content":delta.content})}\n\n'
            if delta.tool_calls:
                for tc in delta.tool_calls:
                    idx = tc.index
                    if idx not in tool_calls_accumulator: tool_calls_accumulator[idx] = {"id": "", "name": "", "args": ""}
                    if tc.id: tool_calls_accumulator[idx]["id"] = tc.id
                    if tc.function and tc.function.name: tool_calls_accumulator[idx]["name"] = tc.function.name
                    if tc.function and tc.function.arguments: tool_calls_accumulator[idx]["args"] += tc.function.arguments
        if finish_reason == "stop" or not tool_calls_accumulator:
            yield f'data: {json.dumps({"type":"done"})}\n\n'
            return
        tool_calls_for_history = [{"id": tc["id"], "type": "function", "function": {"name": tc["name"], "arguments": tc["args"]}} for tc in tool_calls_accumulator.values()]
        history.append({"role": "assistant", "content": full_content or None, "tool_calls": tool_calls_for_history})
        for tc in tool_calls_accumulator.values():
            try: args = json.loads(tc["args"]) if tc["args"] else {}
            except Exception: args = {}
            yield f'data: {json.dumps({"type":"tool_call","name":tc["name"],"args":args})}\n\n'
            try: result = await on_tool_call(tc["name"], args)
            except Exception as e: result = f"ERROR: {e}"
            yield f'data: {json.dumps({"type":"tool_result","name":tc["name"],"result":str(result)[:2000]})}\n\n'
            history.append({"role": "tool", "content": str(result)[:8000], "tool_call_id": tc["id"]})
    yield f'data: {json.dumps({"type":"error","content":"Max tool call rounds reached."})}\n\n'


# ── Non-streaming single-turn completion ──────────────────────────────────────

async def complete(system: str, user_msg: str, model: str | None = None) -> dict:
    """
    Single-turn, non-streaming completion with a custom system prompt.

    Returns:
        {"text": str, "usage": {"input_tokens": int, "output_tokens": int, "model": str}}
    """
    c = _llm_creds()
    if c["anthropic_key"] and c["anthropic_endpoint"]:
        return await _complete_anthropic(system, user_msg, model=model)
    if c["azure_key"] and c["azure_endpoint"]:
        return await _complete_openai(system, user_msg, use_azure=True)
    if c["openai_key"]:
        return await _complete_openai(system, user_msg, use_azure=False)
    raise RuntimeError("No LLM provider configured in .env")


async def _complete_anthropic(system: str, user_msg: str, model: str | None = None) -> dict:
    c = _llm_creds()
    anthropic_model = model or c["anthropic_model"]
    url = c["anthropic_endpoint"]
    if "api-version" not in url:
        url += "?api-version=2024-10-31-preview"
    headers = {
        "Authorization": f"Bearer {c['anthropic_key']}",
        "api-key": c["anthropic_key"],
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }

    # Try decreasing token budgets until the deployment accepts the request.
    # Starts at AZURE_ANTHROPIC_MAX_TOKENS (default 8192 — claude-sonnet-4-6 documented max).
    configured = c["anthropic_max_tokens"]
    budgets = sorted({configured, min(configured, 8192), min(configured, 4096)}, reverse=True)

    last_err: str = ""
    for max_tok in budgets:
        payload = {
            "model": anthropic_model,
            "messages": [{"role": "user", "content": user_msg}],
            "system": system,
            "max_tokens": max_tok,
            "stream": False,
        }
        async with httpx.AsyncClient() as client:
            r = await client.post(url, json=payload, headers=headers, timeout=180.0)

            if r.status_code in (400, 422):
                try:
                    err_body = r.json()
                    last_err = (
                        err_body.get("error", {}).get("message")
                        or str(err_body)
                    )[:500]
                except Exception:
                    last_err = r.text[:500]
                low = last_err.lower()
                if any(kw in low for kw in ("max_tokens", "maximum", "too large", "token")):
                    logger.warning("Anthropic: max_tokens=%d rejected (%s), retrying lower", max_tok, last_err)
                    continue
                raise RuntimeError(f"Anthropic API {r.status_code}: {last_err}")

            if r.status_code != 200:
                last_err = r.text[:500]
                raise RuntimeError(f"Anthropic API {r.status_code}: {last_err}")

            data = r.json()

            # Azure sometimes wraps errors inside a 200 response
            if data.get("type") == "error":
                raise RuntimeError(
                    f"Anthropic error: {data.get('error', {}).get('message', str(data))}"
                )

            usage    = data.get("usage", {})
            text     = data["content"][0]["text"]
            stop_why = data.get("stop_reason", "")
            total_in  = usage.get("input_tokens", 0)
            total_out = usage.get("output_tokens", 0)
            logger.info("Anthropic: max_tokens=%d used=%d stop=%s", max_tok, total_out, stop_why)

            # Continuation loop — re-call up to 3 times if the model was cut off
            for _pass in range(3):
                if stop_why != "max_tokens" or not text:
                    break
                logger.info("Anthropic: truncated at pass %d, continuing…", _pass + 1)
                cont_payload = {
                    "model":      anthropic_model,
                    "messages":   [
                        {"role": "user",      "content": user_msg},
                        {"role": "assistant", "content": text},
                        {"role": "user",      "content":
                            "Continue the report exactly where it was cut off. "
                            "Do not add any preamble, heading, or repetition — "
                            "just resume writing from the last incomplete sentence or section."},
                    ],
                    "system":     system,
                    "max_tokens": max_tok,
                    "stream":     False,
                }
                async with httpx.AsyncClient() as cont_client:
                    cr = await cont_client.post(url, json=cont_payload, headers=headers, timeout=180.0)
                    if cr.status_code != 200:
                        logger.warning("Anthropic continuation %d failed: %s", _pass + 1, cr.text[:200])
                        break
                    cd       = cr.json()
                    cu       = cd.get("usage", {})
                    text    += cd["content"][0]["text"]
                    stop_why = cd.get("stop_reason", "")
                    total_out += cu.get("output_tokens", 0)

            return {
                "text": text,
                "usage": {
                    "input_tokens":  total_in,
                    "output_tokens": total_out,
                    "model":         anthropic_model,
                },
            }

    raise RuntimeError(f"Anthropic API rejected all max_tokens budgets. Last error: {last_err}")


async def _complete_openai(system: str, user_msg: str, *, use_azure: bool) -> dict:
    from openai import AsyncAzureOpenAI, AsyncOpenAI, BadRequestError as OAIBadRequest
    c = _llm_creds()
    if use_azure:
        client = AsyncAzureOpenAI(
            azure_endpoint=c["azure_endpoint"],
            api_key=c["azure_key"],
            api_version=c["azure_version"],
            timeout=180.0,
        )
        model = c["azure_deploy"]
    else:
        client = AsyncOpenAI(api_key=c["openai_key"], timeout=180.0)
        model = c["openai_model"]

    # Try decreasing token budgets until the deployment accepts the request
    # Azure GPT-4o on older API versions (2024-02-01) caps at 4096
    last_err: str = ""
    for max_tok in (16384, 8192, 4096):
        try:
            resp = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.1,
                max_tokens=max_tok,
            )
        except OAIBadRequest as e:
            last_err = f"{type(e).__name__}: {e}"
            low = last_err.lower()
            if any(kw in low for kw in ("max_tokens", "maximum", "context length", "token", "exceed")):
                logger.warning("OpenAI: max_tokens=%d rejected (%s), retrying lower", max_tok, last_err[:200])
                continue
            # A different 400 error — raise immediately with full details
            raise RuntimeError(f"OpenAI BadRequestError: {type(e).__name__}: {e}") from e
        except Exception as e:
            raise RuntimeError(f"OpenAI API error: {type(e).__name__}: {e}") from e

        u         = resp.usage
        text      = resp.choices[0].message.content or ""
        finish    = resp.choices[0].finish_reason
        total_in  = u.prompt_tokens if u else 0
        total_out = u.completion_tokens if u else 0
        logger.info("OpenAI: model=%s max_tokens=%d used=%d finish=%s", model, max_tok, total_out, finish)

        # Continuation loop — re-call up to 3 times if the model was cut off
        for _pass in range(3):
            if finish != "length" or not text:
                break
            logger.info("OpenAI: truncated at pass %d, continuing…", _pass + 1)
            try:
                cont = await client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system",    "content": system},
                        {"role": "user",      "content": user_msg},
                        {"role": "assistant", "content": text},
                        {"role": "user",      "content":
                            "Continue the report exactly where it was cut off. "
                            "Do not add any preamble, heading, or repetition — "
                            "just resume writing from the last incomplete sentence or section."},
                    ],
                    temperature=0.1,
                    max_tokens=max_tok,
                )
                text   += cont.choices[0].message.content or ""
                finish  = cont.choices[0].finish_reason
                if cont.usage:
                    total_out += cont.usage.completion_tokens
            except Exception as ce:
                logger.warning("OpenAI continuation pass %d failed: %s", _pass + 1, ce)
                break

        return {
            "text": text,
            "usage": {
                "input_tokens":  total_in,
                "output_tokens": total_out,
                "model":         model,
            },
        }

    raise RuntimeError(f"OpenAI API rejected all max_tokens budgets. Last error: {last_err}")


async def summarize_investigation(data: dict) -> str:
    """Non-streaming summary of investigation findings."""
    prompt = f"""Summarize the following security investigation findings for user {data['upn']}.
Risk Level: {data['risk_level']}
Risk Factors: {', '.join(data['risk_factors'])}
Mitigating Factors: {', '.join(data['mitigating_factors'])}
Stats: {data['anomalies_count']} anomalies, {data['incident_count']} incidents, {data['total_signins']} sign-ins.

Provide a concise 1-2 paragraph executive summary with bulleted key findings."""
    
    messages = [{"role": "user", "content": prompt}]
    full_text = ""
    # We reuse the existing streaming logic but aggregate it
    async for chunk in stream_chat(messages, None, None):
        if chunk.startswith("data: "):
            payload = json.loads(chunk[6:])
            if payload["type"] == "delta":
                full_text += payload["content"]
            elif payload["type"] == "error":
                raise Exception(payload["content"])
    return full_text
