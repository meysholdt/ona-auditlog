from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gitpod import Gitpod


def to_payload(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, dict):
        return {key: to_payload(item) for key, item in value.items()}

    if isinstance(value, list):
        return [to_payload(item) for item in value]

    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True)

    if hasattr(value, "dict"):
        return value.dict(by_alias=True)

    if hasattr(value, "__dict__"):
        return {key: to_payload(item) for key, item in vars(value).items()}

    return value


def attr(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


@dataclass
class Enrichment:
    creator_email: str | None = None
    git_repo_url: str | None = None
    agent_conversation_s3_url: str | None = None

    def to_payload(self) -> dict[str, str]:
        fields = (
            ("creatorEmail", self.creator_email),
            ("gitRepoUrl", self.git_repo_url),
            ("agentConversationS3Url", self.agent_conversation_s3_url),
        )
        return {key: value for key, value in fields if value is not None}


@dataclass
class EnrichmentResult:
    enrichment: Enrichment
    details: list[dict[str, Any]]


class AuditLogEnricher:
    def __init__(
        self,
        client: Gitpod,
        *,
        environment_cache: dict[str, dict[str, Any] | None] | None = None,
        user_cache: dict[str, dict[str, Any] | None] | None = None,
        runner_cache: dict[str, dict[str, Any] | None] | None = None,
    ) -> None:
        self.client = client
        self.environment_cache = environment_cache if environment_cache is not None else {}
        self.user_cache = user_cache if user_cache is not None else {}
        self.runner_cache = runner_cache if runner_cache is not None else {}

    def prime_from_audit_log(self, entry: Any) -> list[dict[str, Any]]:
        details: list[dict[str, Any]] = []
        if attr(entry, "subject_type") != "RESOURCE_TYPE_ENVIRONMENT":
            return details

        environment_id = attr(entry, "subject_id")
        if not environment_id:
            return details

        try:
            environment, fetched = self._cached_environment(environment_id)
            if fetched:
                self._write_detail(details, "environment", environment)
        except Exception:
            pass
        return details

    def enrich(self, entry: Any, kind: str) -> EnrichmentResult:
        subject_id = attr(entry, "subject_id")
        subject_type = attr(entry, "subject_type")
        details: list[dict[str, Any]] = []
        enrichment = Enrichment()
        creator_resource: dict[str, Any] | None = None
        agent_execution: dict[str, Any] | None = None
        runner: dict[str, Any] | None = None
        environments: list[dict[str, Any] | None] = []

        if subject_type == "RESOURCE_TYPE_ENVIRONMENT":
            try:
                environment, fetched = self._cached_environment(subject_id)
                creator_resource = environment
                environments.append(environment)
                if fetched:
                    self._write_detail(details, "environment", environment)
                runner = self._environment_runner(environment, details)
            except Exception:
                pass

        if subject_type == "RESOURCE_TYPE_AGENT_EXECUTION":
            try:
                agent_execution = self._agent_execution_enrichment(subject_id)
                creator_resource = agent_execution
                self._write_detail(details, "agentExecution", agent_execution)
            except Exception:
                agent_execution = None

            for environment_id in environment_ids_from_agent_execution(agent_execution):
                try:
                    environment, fetched = self._cached_environment(environment_id)
                    environments.append(environment)
                    if fetched:
                        self._write_detail(details, "environment", environment)
                    runner = runner or self._environment_runner(environment, details)
                except Exception:
                    pass

        email = self._creator_email(entry, creator_resource, details)
        if email:
            enrichment.creator_email = email

        environment = environment_with_git_repo(environments)
        repo_url = git_repo_url(environment)
        if repo_url:
            enrichment.git_repo_url = repo_url

        if kind.startswith("agent_execution."):
            conversation_url = conversation_s3_url(agent_execution, runner)
            if conversation_url:
                enrichment.agent_conversation_s3_url = conversation_url

        return EnrichmentResult(enrichment=enrichment, details=details)

    def _user_enrichment(self, user_id: str | None) -> dict[str, Any] | None:
        if not user_id:
            return None

        response = self.client.users.get_user(user_id=user_id)
        return to_payload(response.user)

    def _environment_enrichment(self, environment_id: str | None) -> dict[str, Any] | None:
        if not environment_id:
            return None

        response = self.client.environments.retrieve(environment_id=environment_id)
        return to_payload(response.environment)

    def _agent_execution_enrichment(self, agent_execution_id: str | None) -> dict[str, Any] | None:
        if not agent_execution_id:
            return None

        response = self.client.agents.retrieve_execution(agent_execution_id=agent_execution_id)
        return to_payload(response.agent_execution)

    def _runner_enrichment(self, runner_id: str | None) -> dict[str, Any] | None:
        if not runner_id:
            return None

        response = self.client.runners.retrieve(runner_id=runner_id)
        return to_payload(response.runner)

    def _cached_environment(self, environment_id: str | None) -> tuple[dict[str, Any] | None, bool]:
        if not environment_id:
            return None, False

        cached = None
        if environment_id in self.environment_cache:
            cached = self.environment_cache[environment_id]
            if git_repo_url(cached):
                return cached, False

        try:
            environment = self._environment_enrichment(environment_id)
        except Exception:
            if cached is not None:
                return cached, False
            raise

        self.environment_cache[environment_id] = environment
        return environment, True

    def _creator_email(
        self,
        entry: Any,
        resource: dict[str, Any] | None,
        details: list[dict[str, Any]],
    ) -> str | None:
        user_id = actor_user_id(entry) or creator_user_id(resource)
        if not user_id:
            return None

        try:
            if user_id in self.user_cache:
                user = self.user_cache[user_id]
            else:
                user = self._user_enrichment(user_id)
                self.user_cache[user_id] = user
                self._write_detail(details, "user", user)
            return (user or {}).get("email")
        except Exception:
            return None

    def _environment_runner(
        self,
        environment: dict[str, Any] | None,
        details: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        runner_id = runner_id_from_environment(environment)
        if not runner_id:
            return None

        try:
            if runner_id in self.runner_cache:
                return self.runner_cache[runner_id]

            runner = self._runner_enrichment(runner_id)
            self.runner_cache[runner_id] = runner
            self._write_detail(details, "runner", runner)
            return runner
        except Exception:
            return None

    @staticmethod
    def _write_detail(details: list[dict[str, Any]], kind: str, detail: dict[str, Any] | None) -> None:
        if detail is None:
            return
        details.append({"kind": kind, "object": detail})


def environment_ids_from_agent_execution(agent_execution: dict[str, Any] | None) -> list[str]:
    if not agent_execution:
        return []

    environment_ids: list[str] = []
    status = agent_execution.get("status") or {}
    for used_environment in status.get("usedEnvironments") or status.get("used_environments") or []:
        environment_id = used_environment.get("environmentId") or used_environment.get("environment_id")
        if environment_id:
            environment_ids.append(environment_id)

    spec = agent_execution.get("spec") or {}
    code_context = spec.get("codeContext") or spec.get("code_context") or {}
    for key in ("environmentId", "baseEnvironmentId"):
        environment_id = code_context.get(key)
        if environment_id:
            environment_ids.append(environment_id)
    for key in ("environment_id", "base_environment_id"):
        environment_id = code_context.get(key)
        if environment_id:
            environment_ids.append(environment_id)

    return list(dict.fromkeys(environment_ids))


def git_repo_url(environment: dict[str, Any] | None) -> str | None:
    if not environment:
        return None

    status_git = (((environment.get("status") or {}).get("content") or {}).get("git") or {})
    clone_url = status_git.get("cloneUrl") or status_git.get("clone_url")
    if clone_url:
        return clone_url

    initializer = (((environment.get("spec") or {}).get("content") or {}).get("initializer") or {})
    for spec in initializer.get("specs") or []:
        git = spec.get("git") or {}
        remote_uri = git.get("remoteUri") or git.get("remote_uri")
        if remote_uri:
            return remote_uri

    return None


def environment_with_git_repo(environments: list[dict[str, Any] | None]) -> dict[str, Any] | None:
    for candidate in environments:
        if git_repo_url(candidate):
            return candidate

    return next(iter(environments), None)


def runner_id_from_environment(environment: dict[str, Any] | None) -> str | None:
    if not environment:
        return None
    metadata = environment.get("metadata") or {}
    return metadata.get("runnerId") or metadata.get("runner_id")


def nested_get(value: dict[str, Any] | None, *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def first_s3_url(value: Any) -> str | None:
    if isinstance(value, str):
        if value.startswith("s3://"):
            return value
        return None

    if isinstance(value, dict):
        for item in value.values():
            result = first_s3_url(item)
            if result:
                return result

    if isinstance(value, list):
        for item in value:
            result = first_s3_url(item)
            if result:
                return result

    return None


def conversation_s3_url(agent_execution: dict[str, Any] | None, runner: dict[str, Any] | None = None) -> str | None:
    if not agent_execution:
        return None

    for candidate in (
        nested_get(agent_execution, "status", "conversationUrl"),
        nested_get(agent_execution, "status", "conversation_url"),
        nested_get(agent_execution, "status", "conversationUrls", "history"),
        nested_get(agent_execution, "status", "conversation_urls", "history"),
    ):
        if isinstance(candidate, str) and candidate.startswith("s3://"):
            return candidate

    execution_id = agent_execution.get("id")
    if not execution_id:
        return None

    bucket_url = first_s3_url(runner)
    if not bucket_url:
        return None

    bucket = bucket_url.removeprefix("s3://").split("/", 1)[0]
    if not bucket:
        return None

    return f"s3://{bucket}/conversations/{execution_id}/chunks/"


def actor_user_id(entry: Any) -> str | None:
    if attr(entry, "actor_principal") == "PRINCIPAL_USER":
        return attr(entry, "actor_id")
    return None


def creator_user_id(resource: dict[str, Any] | None) -> str | None:
    if not resource:
        return None

    metadata = resource.get("metadata") or {}
    creator = metadata.get("creator") or {}
    if creator.get("principal") != "PRINCIPAL_USER":
        return None
    return creator.get("id")
