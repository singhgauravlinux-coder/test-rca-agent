import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from kubernetes.client.rest import ApiException

from .analyzer import AnalyzerError, analyze
from .collector import KubeCollector, redact
from .config import get_settings
from .models import RCARequest, RCAResult, RawRCARequest

log = logging.getLogger("rca-agent")
logging.basicConfig(level=logging.INFO)

settings = get_settings()
collector = KubeCollector()

app = FastAPI(title="AI RCA Agent", version="1.0.0")
if settings.cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins,
                       allow_methods=["*"], allow_headers=["*"])


def _check_ns(namespace: str) -> None:
    if settings.allowed_namespaces and namespace not in settings.allowed_namespaces:
        raise HTTPException(403, f"namespace '{namespace}' is not allowed")


def _k8s_error(e: Exception) -> HTTPException:
    if isinstance(e, ApiException):
        return HTTPException(e.status if e.status in (401, 403, 404) else 502,
                             f"Kubernetes API: {e.reason}")
    return HTTPException(503, f"Kubernetes unavailable: {e}")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/api/config")
def get_config():
    return {
        "model": "demo" if settings.demo_mode else settings.gemini_model,
        "demo": settings.demo_mode,
        "ai_configured": settings.demo_mode or bool(settings.gemini_api_key),
        "allowed_namespaces": settings.allowed_namespaces,
    }


@app.get("/api/namespaces")
def namespaces():
    if settings.allowed_namespaces:
        return settings.allowed_namespaces
    try:
        return collector.list_namespaces()
    except Exception as e:
        raise _k8s_error(e)


@app.get("/api/pods")
def pods(namespace: str):
    _check_ns(namespace)
    try:
        return collector.list_pods(namespace)
    except Exception as e:
        raise _k8s_error(e)


@app.post("/api/rca", response_model=RCAResult)
def rca(req: RCARequest):
    _check_ns(req.namespace)
    try:
        ctx = collector.gather(req.namespace, req.pod, req.container, req.tail_lines,
                               req.since_minutes, req.include_previous, settings.max_context_chars)
    except Exception as e:
        raise _k8s_error(e)
    try:
        return analyze(settings, namespace=ctx.namespace, pod=ctx.pod, containers=ctx.containers,
                       pod_status=ctx.pod_status, events=ctx.events, event_count=ctx.event_count,
                       logs=ctx.logs)
    except AnalyzerError as e:
        log.error("analysis failed: %s", e)
        raise HTTPException(502, str(e))


@app.post("/api/rca/raw", response_model=RCAResult)
def rca_raw(req: RawRCARequest):
    """Paste logs/events from anywhere (kubectl, Loki, ELK) - no cluster access needed."""
    logs, events = redact(req.logs), redact(req.events)
    try:
        return analyze(settings, namespace="pasted", pod=req.service, containers=[req.service],
                       pod_status="(not provided)", events=events,
                       event_count=len([x for x in events.splitlines() if x.strip()]), logs=logs)
    except AnalyzerError as e:
        raise HTTPException(502, str(e))
