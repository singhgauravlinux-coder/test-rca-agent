"""Reads pod status, container logs and events from the Kubernetes API (read-only)."""
import json
import re
from dataclasses import dataclass, field
from typing import Optional

from kubernetes import client, config

SECRET_PATTERNS = [
    # Bearer first: otherwise the generic rule below swallows the word "Bearer" and leaks the token
    (re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"), "Bearer ***REDACTED***"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)(\"?\s*[:=]\s*\"?)([^\s\"',;&]+)"),
     r"\1\2***REDACTED***"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "***AWS_KEY***"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "***JWT***"),
    (re.compile(r"(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://([^:\s/]+):([^@\s]+)@"),
     r"\1://\2:***REDACTED***@"),
]


def redact(text: str) -> str:
    for pattern, repl in SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def truncate(text: str, max_chars: int) -> str:
    """Keep the start (boot context) and, mostly, the end (where the failure is)."""
    if len(text) <= max_chars:
        return text
    head = int(max_chars * 0.15)
    tail = max_chars - head
    return f"{text[:head]}\n... [{len(text) - max_chars} chars truncated] ...\n{text[-tail:]}"


@dataclass
class PodContext:
    namespace: str
    pod: str
    containers: list[str]
    pod_status: str
    logs: str
    events: str
    event_count: int
    log_chars: int = 0
    notes: list[str] = field(default_factory=list)


class KubeCollector:
    def __init__(self) -> None:
        self._core: Optional[client.CoreV1Api] = None

    @property
    def core(self) -> client.CoreV1Api:
        if self._core is None:
            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config()
            self._core = client.CoreV1Api()
        return self._core

    # ---- discovery -------------------------------------------------------
    def list_namespaces(self) -> list[str]:
        return sorted(n.metadata.name for n in self.core.list_namespace().items)

    def list_pods(self, namespace: str) -> list[dict]:
        out = []
        for p in self.core.list_namespaced_pod(namespace).items:
            statuses = p.status.container_statuses or []
            waiting = next(
                (s.state.waiting.reason for s in statuses if s.state and s.state.waiting), None
            )
            terminated = next(
                (s.state.terminated.reason for s in statuses if s.state and s.state.terminated), None
            )
            out.append({
                "name": p.metadata.name,
                "phase": p.status.phase,
                "reason": waiting or terminated or p.status.reason,
                "restarts": sum(s.restart_count for s in statuses),
                "ready": f"{sum(1 for s in statuses if s.ready)}/{len(p.spec.containers)}",
                "containers": [c.name for c in p.spec.containers],
                "unhealthy": bool(waiting or terminated)
                or p.status.phase not in ("Running", "Succeeded")
                or any(not s.ready for s in statuses),
            })
        # unhealthy first
        out.sort(key=lambda x: (not x["unhealthy"], -x["restarts"], x["name"]))
        return out

    # ---- gathering -------------------------------------------------------
    def _pod_status(self, pod) -> str:
        containers = []
        specs = {c.name: c for c in pod.spec.containers}
        for s in pod.status.container_statuses or []:
            st = s.state
            last = s.last_state
            res = specs[s.name].resources
            containers.append({
                "name": s.name,
                "image": s.image,
                "ready": s.ready,
                "restartCount": s.restart_count,
                "state": _state(st),
                "lastState": _state(last),
                "resources": {
                    "requests": res.requests if res else None,
                    "limits": res.limits if res else None,
                },
            })
        return json.dumps({
            "phase": pod.status.phase,
            "reason": pod.status.reason,
            "message": pod.status.message,
            "node": pod.spec.node_name,
            "conditions": [
                {"type": c.type, "status": c.status, "reason": c.reason, "message": c.message}
                for c in (pod.status.conditions or [])
            ],
            "containers": containers,
        }, indent=2, default=str)

    def _events(self, namespace: str, pod: str) -> tuple[str, int]:
        evs = self.core.list_namespaced_event(
            namespace, field_selector=f"involvedObject.name={pod}"
        ).items

        def ts(e):
            return e.last_timestamp or e.event_time or e.first_timestamp or e.metadata.creation_timestamp

        evs.sort(key=lambda e: str(ts(e)))
        lines = [
            f"{ts(e)} {e.type} {e.reason} x{e.count or 1}: {e.message}" for e in evs
        ]
        return "\n".join(lines), len(lines)

    def _logs(self, namespace, pod, container, tail, since_minutes, previous) -> str:
        try:
            return self.core.read_namespaced_pod_log(
                pod, namespace, container=container, tail_lines=tail,
                since_seconds=since_minutes * 60 if since_minutes else None,
                previous=previous, timestamps=True,
            )
        except client.ApiException as e:
            if e.status == 400:  # no previous container / container not started yet
                return ""
            raise

    def gather(self, namespace: str, pod: str, container: Optional[str], tail_lines: int,
               since_minutes: Optional[int], include_previous: bool, max_chars: int) -> PodContext:
        p = self.core.read_namespaced_pod(pod, namespace)
        names = [container] if container else [c.name for c in p.spec.containers]
        restarts = {s.name: s.restart_count for s in (p.status.container_statuses or [])}
        events, n_events = self._events(namespace, pod)

        chunks, notes = [], []
        per_container = max(max_chars // max(len(names), 1) // 2, 2000)
        for name in names:
            cur = self._logs(namespace, pod, name, tail_lines, since_minutes, False)
            if cur.strip():
                chunks.append(f"=== container={name} (current) ===\n{truncate(redact(cur), per_container)}")
            else:
                notes.append(f"container {name}: no current logs")
            if include_previous and restarts.get(name, 0) > 0:
                prev = self._logs(namespace, pod, name, tail_lines, since_minutes, True)
                if prev.strip():
                    chunks.append(
                        f"=== container={name} (PREVIOUS crashed instance) ===\n"
                        f"{truncate(redact(prev), per_container)}"
                    )
        logs = "\n\n".join(chunks)
        return PodContext(
            namespace=namespace, pod=pod, containers=names,
            pod_status=self._pod_status(p), logs=logs,
            events=redact(events), event_count=n_events,
            log_chars=len(logs), notes=notes,
        )


def _state(st) -> Optional[dict]:
    if st is None:
        return None
    if st.running:
        return {"running": {"startedAt": str(st.running.started_at)}}
    if st.waiting:
        return {"waiting": {"reason": st.waiting.reason, "message": st.waiting.message}}
    if st.terminated:
        t = st.terminated
        return {"terminated": {
            "reason": t.reason, "exitCode": t.exit_code, "signal": t.signal,
            "message": t.message, "startedAt": str(t.started_at), "finishedAt": str(t.finished_at),
        }}
    return None
