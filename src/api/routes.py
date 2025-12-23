"""
API routes for the LLM Secure Gateway
"""

import time
from typing import List
from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.responses import HTMLResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from pydantic import BaseModel

from ..models import QueryRequest, QueryResponse, HealthResponse
from ..security import validate_api_key, detect_pii, detect_prompt_injection, detect_toxicity
from ..llm.client import llm_client
from ..config import RATE_LIMIT, SERVICE_API_KEY
from ..metrics import metrics
from ..providers import PROVIDER_CONFIG, estimate_cost


# --- Request Models for Batch Endpoints ---
class BatchRequest(BaseModel):
    prompts: List[str]

# --- Router Setup ---
router = APIRouter()
limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT])

@router.get("/", include_in_schema=False)
async def read_root():
    """Serves the Interactive Gateway Demo Dashboard"""
    import os
    from fastapi.responses import FileResponse

    # Path to static HTML file
    static_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "static", "index.html")

    # Read and inject API key for demo experience
    with open(static_path, "r") as f:
        html_content = f.read()

    # Inject the actual service API key for the demo
    html_with_key = html_content.replace('value="secure-demo-ak7x9..."', f'value="{SERVICE_API_KEY}"')
    return HTMLResponse(content=html_with_key, media_type="text/html")

@router.get("/health", response_model=HealthResponse)
async def health_check(request: Request):
    """Health check endpoint"""
    active_provider = None
    if llm_client.providers:
        active_provider = llm_client.providers[0]["name"]
    return HealthResponse(
        status="healthy",
        provider=active_provider,
        timestamp=time.time()
    )

@router.post("/query", response_model=QueryResponse)
@limiter.limit(RATE_LIMIT)
async def query_llm(request: Request, query: QueryRequest, api_key: str = Depends(validate_api_key)):
    """Query LLM with security and fallback protocols"""

    # 1. Input Validation is handled by Pydantic models automatically before this line

    # 2. Execute Logic
    response_content, provider_used, latency_ms, error_message, cascade_path = await llm_client.query_llm_cascade(
        prompt=query.prompt,
        max_tokens=query.max_tokens,
        temperature=query.temperature
    )

    if response_content:
        # Estimate cost (rough estimate based on max_tokens)
        cost_estimate = None
        if provider_used:
            for provider in llm_client.providers:
                if provider["name"] == provider_used:
                    cost_estimate = estimate_cost(
                        provider_used,
                        provider["model"],
                        len(query.prompt.split()) * 2,  # rough input token estimate
                        query.max_tokens // 2  # assume half of max used
                    )
                    break

        # Record metrics
        metrics.record_request(
            provider=provider_used,
            latency_ms=latency_ms,
            blocked=False
        )

        return QueryResponse(
            response=response_content,
            provider=provider_used,
            latency_ms=latency_ms,
            status="success",
            error=None,
            cascade_path=cascade_path,
            cost_estimate_usd=cost_estimate
        )
    else:
        # Record failed request
        metrics.record_request(cascade_failed=True)

        # Fallback failure
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_message or "All LLM providers failed."
        )


@router.get("/metrics")
async def get_metrics():
    """Return current gateway metrics"""
    return metrics.to_dict()


@router.get("/providers")
async def get_providers():
    """Return available providers with pricing info"""
    active_providers = [p["name"] for p in llm_client.providers]
    return {
        "providers": PROVIDER_CONFIG,
        "active_providers": active_providers,
        "active_models": {p["name"]: p["model"] for p in llm_client.providers}
    }


@router.post("/batch/resilience")
async def batch_resilience_test(
    request: Request,
    batch: BatchRequest,
    api_key: str = Depends(validate_api_key)
):
    """Run multiple prompts through the cascade, return aggregate metrics"""
    results = []
    total_failures = 0
    total_latency = 0

    # Limit to 10 prompts for PoC
    prompts = batch.prompts[:10]

    for prompt in prompts:
        try:
            response, provider, latency, error, cascade_path = await llm_client.query_llm_cascade(
                prompt=prompt,
                max_tokens=256,
                temperature=0.7
            )

            failures_in_cascade = sum(1 for step in cascade_path if step["status"] == "failed")
            total_failures += failures_in_cascade

            if response:
                total_latency += latency
                metrics.record_request(provider=provider, latency_ms=latency)
            else:
                metrics.record_request(cascade_failed=True)

            results.append({
                "prompt": prompt[:50] + "..." if len(prompt) > 50 else prompt,
                "success": response is not None,
                "provider": provider,
                "latency_ms": latency,
                "cascade_path": cascade_path,
                "failures_in_cascade": failures_in_cascade
            })
        except Exception as e:
            results.append({
                "prompt": prompt[:50] + "..." if len(prompt) > 50 else prompt,
                "success": False,
                "error": str(e)
            })

    successful = sum(1 for r in results if r.get("success"))
    avg_latency = total_latency / successful if successful > 0 else 0

    return {
        "total": len(results),
        "successful": successful,
        "failed": len(results) - successful,
        "total_cascade_failures": total_failures,
        "average_latency_ms": round(avg_latency, 2),
        "downtime_prevented_minutes": round(total_failures * 4, 1),  # 4 min per failure
        "results": results
    }


@router.post("/batch/security")
async def batch_security_test(batch: BatchRequest):
    """Test prompts for security issues without executing LLM calls"""
    results = []
    total_blocked = 0
    pii_leaks = 0
    injection_attempts = 0

    for prompt in batch.prompts[:20]:  # Limit to 20
        pii_result = detect_pii(prompt)
        injection_detected = detect_prompt_injection(prompt)

        blocked = pii_result["has_pii"] or injection_detected

        if blocked:
            total_blocked += 1
        if pii_result["has_pii"]:
            pii_leaks += len(pii_result["pii_types"])
            metrics.record_request(blocked=True, pii_detected=True)
        if injection_detected:
            injection_attempts += 1
            metrics.record_request(blocked=True, injection_detected=True)

        results.append({
            "prompt": prompt[:50] + "..." if len(prompt) > 50 else prompt,
            "blocked": blocked,
            "pii_detected": pii_result["pii_types"] if pii_result["has_pii"] else [],
            "pii_matches": pii_result["matches"] if pii_result["has_pii"] else {},
            "injection_detected": injection_detected
        })

    # Calculate compliance fines avoided (GDPR ~$50K + CCPA ~$7.5K avg = $28K per violation)
    compliance_fines_avoided = pii_leaks * 28000

    return {
        "total": len(results),
        "blocked": total_blocked,
        "passed": len(results) - total_blocked,
        "pii_leaks_prevented": pii_leaks,
        "injection_attempts_blocked": injection_attempts,
        "compliance_fines_avoided_usd": compliance_fines_avoided,
        "results": results
    }


class ToxicityRequest(BaseModel):
    text: str


@router.post("/check-toxicity")
async def check_toxicity(request: ToxicityRequest):
    """
    Check text for toxic content using Perspective API.
    Returns toxicity scores and blocked categories.
    """
    result = detect_toxicity(request.text)
    return {
        "is_toxic": result["is_toxic"],
        "scores": result["scores"],
        "blocked_categories": result["blocked_categories"],
        "error": result["error"]
    }