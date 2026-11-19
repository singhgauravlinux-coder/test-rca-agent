# WhyBot — AI RCA agent for Kubernetes

Reads **pod status + container logs (incl. the crashed previous instance) + events**, redacts secrets,
and asks **Gemini Flash** (as a principal SRE) for a structured **5-Why root cause analysis**
with evidence, fix-now commands, prevention steps and a confidence score.

```
 browser ─► nginx (frontend, :8080) ─► FastAPI backend (:8000) ─► Kubernetes API (read-only RBAC)
                                                             └──► Gemini API (Flash)
```

## Layout
| Path | What |
|---|---|
| `backend/` | FastAPI: `collector.py` (K8s read + redaction), `analyzer.py` (Gemini, JSON-schema output), `main.py` (API) |
| `frontend/` | Static SPA (no build step) served by nginx-unprivileged, proxies `/api` to backend |
| `k8s/` | Kustomize: namespace, **read-only** RBAC, deployments, services, ingress, NetworkPolicy |
| `.github/workflows/ci.yml` | lint+test → manifest validation → build/push to GHCR → Trivy scan → deploy |

## API
- `GET /api/namespaces`, `GET /api/pods?namespace=`
- `POST /api/rca` `{namespace, pod, container?, tail_lines, since_minutes?, include_previous}`
- `POST /api/rca/raw` `{logs, events?, service?}` — paste logs from anywhere, no cluster access needed

## Try it locally
```bash
# UI only, no key, no cluster:
cd backend && pip install -r requirements.txt && DEMO_MODE=true uvicorn app.main:app --port 8000
# or full stack (uses your ~/.kube/config):
GEMINI_API_KEY=... docker compose up --build      # http://localhost:8080
```
Get a key at https://aistudio.google.com/apikey. Model is set by `GEMINI_MODEL` (default `gemini-2.5-flash`;
set it to any newer Flash id without code changes).

## CI/CD (GitHub Actions)
Repo secrets / settings:
| Name | Purpose |
|---|---|
| `GEMINI_API_KEY` (secret) | written into the `rca-gemini` K8s Secret on deploy |
| `KUBE_CONFIG` (secret) | kubeconfig of a deploy ServiceAccount; **if unset, the deploy job skips** and only images are pushed |
| `production` (environment) | optional: add required reviewers for a manual approval gate |

Before first run, replace `OWNER` in `k8s/*.yaml` is handled by CI on deploy; for manual deploys do
`sed -i 's#ghcr.io/OWNER/#ghcr.io/<you>/#' k8s/*.yaml`, and set your host in `k8s/frontend.yaml` Ingress.
Make the GHCR packages public, or add an `imagePullSecret`.

## Manual deploy
```bash
kubectl apply -f k8s/namespace.yaml
kubectl -n rca-agent create secret generic rca-gemini --from-literal=GEMINI_API_KEY=...
kubectl apply -k k8s
kubectl -n rca-agent port-forward svc/rca-frontend 8080:80
```

## Security notes
- ClusterRole is `get/list` on pods, pods/log, events, namespaces only. Restrict further with `ALLOWED_NAMESPACES`.
- Logs are regex-redacted (passwords, tokens, bearer/JWT, AWS keys, DB URLs) **before** being sent to Gemini; this is best-effort, not a guarantee.
- The UI can read any pod's logs: put the Ingress behind SSO/VPN. Prompts treat logs as untrusted data (prompt-injection hardening), but treat output as advice, not truth.
