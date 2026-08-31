"""
Audit workers — gather empirical evidence from AWS (or mock fixtures).

Each worker implements one of four tools:
  cloudtrail_usage, last_accessed, analyzer_findings, terraform_state

The AuditBackend protocol defines the interface; MockBackend reads scenario
fixtures; LocalStackBackend/AwsBackend are stubs for Tier 2/3.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Protocol

from .schemas import Task, UsageEvidence


# ---------------------------------------------------------------------------
# Backend Protocol
# ---------------------------------------------------------------------------

class AuditBackend(Protocol):
    """Interface for data sources. Implementations: Mock, LocalStack, AWS."""

    def cloudtrail_usage(self, principal: str, days: int,
                         filter_action: Optional[str] = None) -> List[Dict[str, Any]]:
        ...

    def last_accessed(self, principal: str) -> List[Dict[str, Any]]:
        ...

    def analyzer_findings(self, principal: str) -> List[Dict[str, Any]]:
        ...

    def terraform_state(self, principal: str,
                        include_trust: bool = False) -> Dict[str, Any]:
        ...


# ---------------------------------------------------------------------------
# MockBackend — reads scenario fixtures
# ---------------------------------------------------------------------------

class MockBackend:
    """Deterministic backend that reads from scenario fixture data."""

    def __init__(self, fixtures: Dict[str, Any]) -> None:
        self._fixtures = fixtures

    def cloudtrail_usage(self, principal: str, days: int,
                         filter_action: Optional[str] = None) -> List[Dict[str, Any]]:
        events = self._fixtures.get("cloudtrail", [])
        if filter_action:
            events = [e for e in events if e.get("action") == filter_action]
        return events

    def last_accessed(self, principal: str) -> List[Dict[str, Any]]:
        return self._fixtures.get("last_accessed", [])

    def analyzer_findings(self, principal: str) -> List[Dict[str, Any]]:
        return self._fixtures.get("analyzer_findings", [])

    def terraform_state(self, principal: str,
                        include_trust: bool = False) -> Dict[str, Any]:
        state = self._fixtures.get("terraform_state", {})
        result = {
            "current_policy": self._fixtures.get("current_policy", {}),
            "current_hcl": self._fixtures.get("current_hcl", ""),
        }
        if include_trust:
            result["trust_policy"] = state.get("trust_policy", {})
        result.update(state)
        return result


# ---------------------------------------------------------------------------
# Stub backends for Tier 2/3
# ---------------------------------------------------------------------------

class LocalStackBackend:
    """Placeholder for LocalStack (Tier 2). Falls back to MockBackend."""

    def __init__(self, fixtures: Dict[str, Any]) -> None:
        self._mock = MockBackend(fixtures)
        # In real implementation: boto3 client pointed at localhost:4566
        import logging
        logging.getLogger("sentinel.workers").info(
            "LocalStackBackend: falling back to MockBackend (not yet wired)"
        )

    def cloudtrail_usage(self, principal: str, days: int,
                         filter_action: Optional[str] = None) -> List[Dict[str, Any]]:
        return self._mock.cloudtrail_usage(principal, days, filter_action)

    def last_accessed(self, principal: str) -> List[Dict[str, Any]]:
        return self._mock.last_accessed(principal)

    def analyzer_findings(self, principal: str) -> List[Dict[str, Any]]:
        return self._mock.analyzer_findings(principal)

    def terraform_state(self, principal: str,
                        include_trust: bool = False) -> Dict[str, Any]:
        return self._mock.terraform_state(principal, include_trust)


class AwsBackend:
    """
    Real AWS backend (Tier 3) — uses boto3 to query live AWS services.
    
    Falls back to MockBackend for any service that fails or isn't configured.
    To enable: set SENTINEL_BACKEND=aws and configure AWS credentials.
    
    Required IAM permissions for the agent role:
      - cloudtrail:LookupEvents
      - iam:GenerateServiceLastAccessedDetails
      - iam:GetServiceLastAccessedDetails  
      - access-analyzer:ListFindings
      - iam:GetPolicy, iam:GetPolicyVersion, iam:GetRole
      - sts:GetCallerIdentity
    """

    def __init__(self, fixtures: Dict[str, Any]) -> None:
        self._mock = MockBackend(fixtures)
        self._boto_available = False
        self._clients: Dict[str, Any] = {}

        try:
            import boto3
            self._boto_available = True
            endpoint = os.environ.get("AWS_ENDPOINT_URL")
            region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

            client_kwargs: Dict[str, Any] = {"region_name": region}
            if endpoint:
                client_kwargs["endpoint_url"] = endpoint

            self._clients = {
                "cloudtrail": boto3.client("cloudtrail", **client_kwargs),
                "iam": boto3.client("iam", **client_kwargs),
                "accessanalyzer": boto3.client("accessanalyzer", **client_kwargs),
            }
            # Verify connectivity
            sts = boto3.client("sts", **client_kwargs)
            identity = sts.get_caller_identity()
            print(f"[workers] AwsBackend: connected as {identity.get('Arn', '?')}")
        except ImportError:
            print("[workers] AwsBackend: boto3 not installed, falling back to mock")
        except Exception as exc:
            print(f"[workers] AwsBackend: AWS connection failed ({exc}), falling back to mock")

    def cloudtrail_usage(self, principal: str, days: int,
                         filter_action: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self._boto_available:
            return self._mock.cloudtrail_usage(principal, days, filter_action)

        try:
            import datetime
            ct = self._clients["cloudtrail"]
            start_time = datetime.datetime.utcnow() - datetime.timedelta(days=days)

            lookup_attrs = [{"AttributeKey": "Username", "AttributeValue": principal}]
            paginator = ct.get_paginator("lookup_events")
            events: List[Dict[str, Any]] = []

            for page in paginator.paginate(
                LookupAttributes=lookup_attrs,
                StartTime=start_time,
            ):
                for event in page.get("Events", []):
                    action = event.get("EventName", "")
                    service = event.get("EventSource", "").replace(".amazonaws.com", "")
                    full_action = f"{service}:{action}"

                    if filter_action and full_action != filter_action:
                        continue

                    events.append({
                        "action": full_action,
                        "timestamp": event.get("EventTime", "").isoformat()
                            if hasattr(event.get("EventTime", ""), "isoformat")
                            else str(event.get("EventTime", "")),
                        "source_ip": event.get("SourceIPAddress", ""),
                        "user_agent": event.get("UserAgent", ""),
                    })

            return events
        except Exception as exc:
            print(f"[workers] CloudTrail query failed: {exc}")
            return self._mock.cloudtrail_usage(principal, days, filter_action)

    def last_accessed(self, principal: str) -> List[Dict[str, Any]]:
        if not self._boto_available:
            return self._mock.last_accessed(principal)

        try:
            import time as _time
            iam = self._clients["iam"]

            # Determine ARN — principal could be role name or full ARN
            if principal.startswith("arn:"):
                arn = principal
            else:
                try:
                    role = iam.get_role(RoleName=principal)
                    arn = role["Role"]["Arn"]
                except Exception:
                    # Try as user
                    user = iam.get_user(UserName=principal)
                    arn = user["User"]["Arn"]

            job = iam.generate_service_last_accessed_details(Arn=arn)
            job_id = job["JobId"]

            # Poll for completion (max 30s)
            for _ in range(30):
                result = iam.get_service_last_accessed_details(JobId=job_id)
                if result["JobStatus"] == "COMPLETED":
                    return [
                        {
                            "service": svc.get("ServiceNamespace", ""),
                            "last_accessed": svc.get("LastAuthenticated", "").isoformat()
                                if hasattr(svc.get("LastAuthenticated", ""), "isoformat")
                                else str(svc.get("LastAuthenticated", "")),
                            "total_entities": svc.get("TotalAuthenticatedEntities", 0),
                        }
                        for svc in result.get("ServicesLastAccessed", [])
                        if svc.get("LastAuthenticated")
                    ]
                _time.sleep(1)

            return self._mock.last_accessed(principal)
        except Exception as exc:
            print(f"[workers] Last-accessed query failed: {exc}")
            return self._mock.last_accessed(principal)

    def analyzer_findings(self, principal: str) -> List[Dict[str, Any]]:
        if not self._boto_available:
            return self._mock.analyzer_findings(principal)

        try:
            aa = self._clients["accessanalyzer"]

            # List analyzers first
            analyzers = aa.list_analyzers(type="ACCOUNT")
            if not analyzers.get("analyzers"):
                return self._mock.analyzer_findings(principal)

            analyzer_arn = analyzers["analyzers"][0]["arn"]

            findings: List[Dict[str, Any]] = []
            paginator = aa.get_paginator("list_findings")
            for page in paginator.paginate(
                analyzerArn=analyzer_arn,
                filter={"resource": {"contains": [principal]}},
            ):
                for f in page.get("findings", []):
                    findings.append({
                        "finding_id": f.get("id", ""),
                        "resource": f.get("resource", ""),
                        "resource_type": f.get("resourceType", ""),
                        "status": f.get("status", ""),
                        "condition": f.get("condition", {}),
                    })

            return findings if findings else self._mock.analyzer_findings(principal)
        except Exception as exc:
            print(f"[workers] Access Analyzer query failed: {exc}")
            return self._mock.analyzer_findings(principal)

    def terraform_state(self, principal: str,
                        include_trust: bool = False) -> Dict[str, Any]:
        if not self._boto_available:
            return self._mock.terraform_state(principal, include_trust)

        try:
            iam = self._clients["iam"]
            result: Dict[str, Any] = {}

            # Get current inline/attached policies
            try:
                role = iam.get_role(RoleName=principal)
                result["trust_policy"] = role["Role"].get("AssumeRolePolicyDocument", {})

                # Get attached policies
                attached = iam.list_attached_role_policies(RoleName=principal)
                for pol in attached.get("AttachedPolicies", []):
                    policy = iam.get_policy(PolicyArn=pol["PolicyArn"])
                    version_id = policy["Policy"]["DefaultVersionId"]
                    version = iam.get_policy_version(
                        PolicyArn=pol["PolicyArn"], VersionId=version_id)
                    result["current_policy"] = version["PolicyVersion"]["Document"]
                    break  # Use first attached policy

                # Get inline policies
                inline = iam.list_role_policies(RoleName=principal)
                for pol_name in inline.get("PolicyNames", []):
                    pol = iam.get_role_policy(RoleName=principal, PolicyName=pol_name)
                    if "current_policy" not in result:
                        result["current_policy"] = pol["PolicyDocument"]
                    break

            except Exception:
                # Try as user
                attached = iam.list_attached_user_policies(UserName=principal)
                for pol in attached.get("AttachedPolicies", []):
                    policy = iam.get_policy(PolicyArn=pol["PolicyArn"])
                    version_id = policy["Policy"]["DefaultVersionId"]
                    version = iam.get_policy_version(
                        PolicyArn=pol["PolicyArn"], VersionId=version_id)
                    result["current_policy"] = version["PolicyVersion"]["Document"]
                    break

            result.setdefault("current_policy", {})
            result.setdefault("current_hcl", "")
            return result
        except Exception as exc:
            print(f"[workers] Terraform state query failed: {exc}")
            return self._mock.terraform_state(principal, include_trust)


# ---------------------------------------------------------------------------
# Backend factory
# ---------------------------------------------------------------------------

def get_backend(backend_name: str, fixtures: Dict[str, Any]) -> AuditBackend:
    """Return the appropriate backend for the configured tier."""
    if backend_name == "localstack":
        return LocalStackBackend(fixtures)
    elif backend_name == "aws":
        return AwsBackend(fixtures)
    return MockBackend(fixtures)


# ---------------------------------------------------------------------------
# Worker execution
# ---------------------------------------------------------------------------

def run_worker(task: Task, backend: AuditBackend) -> Dict[str, Any]:
    """
    Execute a single audit worker task against the backend.

    Returns the tool output dict. On failure, returns {"error": ...} so
    evidence merge can degrade gracefully.
    """
    try:
        tool = task.tool
        args = task.args

        if tool == "cloudtrail_usage":
            data = backend.cloudtrail_usage(
                principal=args.get("principal", ""),
                days=args.get("days", 90),
                filter_action=args.get("filter_action"),
            )
            return {"tool": tool, "task_id": task.id, "data": data}

        elif tool == "last_accessed":
            data = backend.last_accessed(principal=args.get("principal", ""))
            return {"tool": tool, "task_id": task.id, "data": data}

        elif tool == "analyzer_findings":
            data = backend.analyzer_findings(principal=args.get("principal", ""))
            return {"tool": tool, "task_id": task.id, "data": data}

        elif tool == "terraform_state":
            data = backend.terraform_state(
                principal=args.get("principal", ""),
                include_trust=args.get("include_trust", False),
            )
            return {"tool": tool, "task_id": task.id, "data": data}

        else:
            return {"tool": tool, "task_id": task.id, "error": f"Unknown tool: {tool}"}

    except Exception as exc:
        return {"tool": task.tool, "task_id": task.id, "error": str(exc)}


# ---------------------------------------------------------------------------
# Evidence merge
# ---------------------------------------------------------------------------

def merge_evidence(worker_outputs: List[Dict[str, Any]]) -> UsageEvidence:
    """
    Merge outputs from all audit workers into a single UsageEvidence.

    Tolerates partial/error outputs — records errors and continues with
    whatever data is available.
    """
    evidence = UsageEvidence()
    errors: List[Dict[str, Any]] = []

    for output in worker_outputs:
        if "error" in output:
            errors.append({"task_id": output.get("task_id"), "error": output["error"]})
            continue

        tool = output.get("tool", "")
        data = output.get("data", {})

        if tool == "cloudtrail_usage":
            if isinstance(data, list):
                evidence.used_actions.extend(data)

        elif tool == "last_accessed":
            if isinstance(data, list):
                evidence.last_accessed.extend(data)

        elif tool == "analyzer_findings":
            if isinstance(data, list):
                evidence.analyzer_findings.extend(data)

        elif tool == "terraform_state":
            if isinstance(data, dict):
                if "current_policy" in data:
                    evidence.current_policy = data["current_policy"]
                if "current_hcl" in data:
                    evidence.current_hcl = data.get("current_hcl", "")
                evidence.terraform_state = data

    # Extract granted actions from current policy
    if evidence.current_policy:
        for stmt in evidence.current_policy.get("Statement", []):
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            evidence.granted_actions.extend(actions)

    # Deduplicate
    evidence.granted_actions = sorted(set(evidence.granted_actions))

    evidence.errors = errors
    return evidence
