import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import analyzer, main
from app.collector import PodContext, redact, truncate
from app.config import Settings
from app.models import RCAReport


def test_redact_secrets():
    s = ('password=hunter2 Authorization: Bearer abc.def.ghi api_key="XYZ123" '
         'postgres://user:p4ss@db:5432/x AKIAABCDEFGHIJKLMNOP')
    out = redact(s)
    for leaked in ("hunter2", "abc.def.ghi", "XYZ123", "p4ss", "AKIAABCDEFGHIJKLMNOP"):
        assert leaked not in out
    assert "REDACTED" in out


def test_truncate_keeps_head_and_tail():
    text = "HEAD" + "x" * 10_000 + "TAIL"
    out = truncate(text, 1000)
    assert out.startswith("HEAD") and out.endswith("TAIL")
    assert len(out) < 1200 and "truncated" in out


def test_truncate_noop_when_small():
    assert truncate("abc", 100) == "abc"


def test_build_prompt_contains_sections():
    p = analyzer.build_prompt("ns", "pod", "{}", "Warning BackOff", "boom", 10_000)
    assert "POD STATUS" in p and "KUBERNETES EVENTS" in p and "boom" in p


def test_normalize_orders_and_clamps():
    r = analyzer.demo_report()
    r.severity = "SEVERE"
    r.confidence = 7
    r.five_whys = list(reversed(r.five_whys))
    r = analyzer._normalize(r)
    assert r.severity == "medium" and r.confidence == 1.0
    assert [s.level for s in r.five_whys] == [1, 2, 3, 4, 5]


def test_analyze_requires_key():
    with pytest.raises(analyzer.AnalyzerError):
        analyzer.analyze(Settings(gemini_api_key=""), namespace="n", pod="p", containers=["c"],
                         pod_status="{}", events="", event_count=0, logs="x")


def test_analyze_demo_mode():
    res = analyzer.analyze(Settings(demo_mode=True), namespace="n", pod="p", containers=["c"],
                           pod_status="{}", events="", event_count=0, logs="x")
    assert res.meta.demo and len(res.report.five_whys) == 5


def test_analyze_with_mocked_gemini(monkeypatch):
    payload = analyzer.demo_report().model_dump_json()
    fake_resp = SimpleNamespace(parsed=None, text=payload)

    class FakeModels:
        def generate_content(self, **kw):
            assert "CONTAINER LOGS" in kw["contents"]
            assert kw["model"] == "gemini-test"
            return fake_resp

    class FakeClient:
        def __init__(self, api_key):
            self.models = FakeModels()

    import google.genai as genai
    monkeypatch.setattr(genai, "Client", FakeClient)
    res = analyzer.analyze(Settings(gemini_api_key="k", gemini_model="gemini-test"), namespace="n",
                           pod="p", containers=["c"], pod_status="{}", events="e", event_count=1, logs="l")
    assert isinstance(res.report, RCAReport) and res.meta.model == "gemini-test"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "settings", Settings(demo_mode=True, allowed_namespaces=["prod"]))
    ctx = PodContext("prod", "api-1", ["api"], json.dumps({"phase": "Running"}), "logs", "events", 2, 4)
    monkeypatch.setattr(main.collector, "gather", lambda *a, **k: ctx)
    monkeypatch.setattr(main.collector, "list_pods", lambda ns: [{"name": "api-1"}])
    return TestClient(main.app)


def test_health_and_config(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/api/config").json()["demo"] is True


def test_namespace_allowlist(client):
    assert client.get("/api/pods", params={"namespace": "kube-system"}).status_code == 403
    assert client.get("/api/pods", params={"namespace": "prod"}).status_code == 200


def test_rca_endpoint(client):
    r = client.post("/api/rca", json={"namespace": "prod", "pod": "api-1"})
    assert r.status_code == 200
    assert len(r.json()["report"]["five_whys"]) == 5
    assert client.post("/api/rca", json={"namespace": "other", "pod": "x"}).status_code == 403


def test_rca_raw_endpoint(client):
    r = client.post("/api/rca/raw", json={"logs": "OOMKilled password=abc", "service": "svc"})
    assert r.status_code == 200 and r.json()["meta"]["pod"] == "svc"
    assert client.post("/api/rca/raw", json={"logs": ""}).status_code == 422
