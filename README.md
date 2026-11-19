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
| `.github/workflows/ci.yml` | lint+test → manifest validation → build/push to GHCR → Trivy scan → auto-bump image tags in `k8s/` |

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

## CI (GitHub Actions) — build only, you deploy
Pipeline on every push to `main`: lint + pytest → validate manifests → build & push both images to GHCR
(tags `sha-<commit>`, `latest`) → Trivy scan (report only) → **commit the new image tag + your GitHub owner
into `k8s/kustomization.yaml`** (message ends with `[skip ci]`).
There is no CD job: nothing touches your cluster. No secrets are needed in GitHub (only the built-in `GITHUB_TOKEN`).

If `main` is branch-protected, allow `github-actions[bot]` to push, otherwise the tag-commit step fails.
Make the GHCR packages public (repo → Packages → settings) or create an `imagePullSecret`.

## Deploy yourself with Kustomize
```bash
git pull                                   # picks up the tag commit made by CI
                                           # (first time only: edit host in k8s/frontend.yaml Ingress,
                                           #  and if CI has not run yet: sed -i 's#ghcr.io/OWNER/#ghcr.io/<you>/#' k8s/*.yaml)

# 1. namespace + Gemini key (never committed to git)
kubectl apply -f k8s/namespace.yaml
kubectl -n rca-agent create secret generic rca-gemini \
  --from-literal=GEMINI_API_KEY='<your-key>'

# 2. everything else (RBAC, backend, frontend, NetworkPolicy)
kubectl apply -k k8s

# 3. verify
kubectl -n rca-agent rollout status deploy/rca-backend deploy/rca-frontend
kubectl -n rca-agent get pods

# 4. open the UI
kubectl -n rca-agent port-forward svc/rca-frontend 8080:80      # http://localhost:8080
```
Upgrades: after CI pushes a new tag commit, `git pull && kubectl apply -k k8s`.
Rollback: `kubectl -n rca-agent rollout undo deploy/rca-backend` (or `git revert` the tag commit and re-apply).
Rotate the key: re-run the `create secret ... --dry-run=client -o yaml | kubectl apply -f -` form, then
`kubectl -n rca-agent rollout restart deploy/rca-backend`.

## Security notes
- ClusterRole is `get/list` on pods, pods/log, events, namespaces only. Restrict further with `ALLOWED_NAMESPACES`.
- Logs are regex-redacted (passwords, tokens, bearer/JWT, AWS keys, DB URLs) **before** being sent to Gemini; this is best-effort, not a guarantee.
- The UI can read any pod's logs: put the Ingress behind SSO/VPN. Prompts treat logs as untrusted data (prompt-injection hardening), but treat output as advice, not truth.
