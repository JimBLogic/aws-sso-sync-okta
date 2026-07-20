#!/usr/bin/env python3
"""Safely synchronize selected Okta groups into AWS IAM Identity Center via SCIM.

The command is dry-run by default. Pass --apply to create users, groups and
memberships. It never deletes or disables identities.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Any, Iterable, Iterator
from urllib.parse import urlparse

import boto3
import requests
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound

LOG = logging.getLogger("aws-sso-sync-okta")
USER_AGENT = "aws-sso-sync-okta/1.0"
DEFAULT_GROUPS_PARAMETER = "/aws-sso-sync-okta/groups"
DEFAULT_OKTA_TOKEN_PARAMETER = "/aws-sso-sync-okta/okta-api-token"
DEFAULT_SCIM_TOKEN_PARAMETER = "/aws-sso-sync-okta/scim-access-token"


class SyncError(RuntimeError):
    """A recoverable configuration, API or synchronization error."""


@dataclass(frozen=True)
class Person:
    first_name: str
    last_name: str
    email: str


@dataclass
class Counters:
    users_created: int = 0
    groups_created: int = 0
    memberships_added: int = 0
    unchanged: int = 0


class IdentifierFormatter:
    def __init__(self, show_identifiers: bool) -> None:
        self.show_identifiers = show_identifiers

    def __call__(self, value: str) -> str:
        if self.show_identifiers:
            return value
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        return f"sha256:{digest}"


class HttpClient:
    def __init__(self, timeout: float) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            raise SyncError(f"HTTP request failed for {method} {url}: {exc}") from exc


class OktaClient:
    def __init__(self, domain: str, token: str, http: HttpClient) -> None:
        self.base_url = f"https://{validate_okta_domain(domain)}"
        self.http = http
        self.headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {token}",
        }

    def _iter_pages(
        self, path: str, params: dict[str, Any] | None = None
    ) -> Iterator[list[dict[str, Any]]]:
        url = f"{self.base_url}{path}"
        current_params = params
        while url:
            response = self.http.request(
                "GET", url, headers=self.headers, params=current_params
            )
            payload = response.json()
            if not isinstance(payload, list):
                raise SyncError(f"unexpected Okta response shape for {path}")
            yield payload
            url = response.links.get("next", {}).get("url", "")
            current_params = None

    def find_exact_group(self, name: str) -> dict[str, Any]:
        candidates: list[dict[str, Any]] = []
        for page in self._iter_pages(
            "/api/v1/groups", {"q": name, "limit": 200}
        ):
            candidates.extend(
                group
                for group in page
                if group.get("profile", {}).get("name") == name
            )

        if not candidates:
            raise SyncError(f"Okta group not found: {name}")
        if len(candidates) > 1:
            raise SyncError(f"multiple exact Okta groups returned for: {name}")
        return candidates[0]

    def list_group_users(self, group_id: str) -> list[Person]:
        users: dict[str, Person] = {}
        path = f"/api/v1/groups/{group_id}/users"
        for page in self._iter_pages(path, {"limit": 200}):
            for item in page:
                profile = item.get("profile", {})
                email = str(profile.get("login", "")).strip().lower()
                first_name = str(profile.get("firstName", "")).strip()
                last_name = str(profile.get("lastName", "")).strip()
                if not email or not first_name or not last_name:
                    raise SyncError(
                        f"Okta user in group {group_id} lacks required profile fields"
                    )
                users[email] = Person(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                )
        return list(users.values())


class ScimClient:
    def __init__(self, base_url: str, token: str, http: HttpClient) -> None:
        self.base_url = validate_scim_base_url(base_url)
        self.http = http
        self.headers = {
            "Accept": "application/scim+json, application/json",
            "Content-Type": "application/scim+json",
            "Authorization": f"Bearer {token}",
        }

    def _url(self, resource: str) -> str:
        return f"{self.base_url}/{resource.lstrip('/')}"

    def list_resources(
        self, resource: str, filter_expression: str | None = None
    ) -> list[dict[str, Any]]:
        start_index = 1
        count = 100
        resources: list[dict[str, Any]] = []

        while True:
            params: dict[str, Any] = {
                "startIndex": start_index,
                "count": count,
            }
            if filter_expression:
                params["filter"] = filter_expression
            payload = self.http.request(
                "GET",
                self._url(resource),
                headers=self.headers,
                params=params,
            ).json()
            page = payload.get("Resources", [])
            if not isinstance(page, list):
                raise SyncError(f"unexpected SCIM response shape for {resource}")
            resources.extend(page)

            total = int(payload.get("totalResults", len(resources)))
            items = int(payload.get("itemsPerPage", len(page)))
            if not page or len(resources) >= total or items <= 0:
                break
            start_index += items
        return resources

    def find_user(self, email: str) -> dict[str, Any] | None:
        users = self.list_resources(
            "Users", f'userName eq "{escape_scim_filter(email)}"'
        )
        if len(users) > 1:
            raise SyncError(
                f"multiple IAM Identity Center users found for {email}"
            )
        return users[0] if users else None

    def create_user(self, person: Person) -> dict[str, Any]:
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": person.email,
            "name": {
                "familyName": person.last_name,
                "givenName": person.first_name,
            },
            "displayName": f"{person.first_name} {person.last_name}".strip(),
            "emails": [
                {
                    "value": person.email,
                    "type": "work",
                    "primary": True,
                }
            ],
            "active": True,
        }
        return self.http.request(
            "POST",
            self._url("Users"),
            headers=self.headers,
            json=payload,
        ).json()

    def find_group(self, name: str) -> dict[str, Any] | None:
        groups = self.list_resources(
            "Groups", f'displayName eq "{escape_scim_filter(name)}"'
        )
        if len(groups) > 1:
            raise SyncError(
                f"multiple IAM Identity Center groups found for {name}"
            )
        return groups[0] if groups else None

    def create_group(self, name: str) -> dict[str, Any]:
        payload = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": name,
        }
        return self.http.request(
            "POST",
            self._url("Groups"),
            headers=self.headers,
            json=payload,
        ).json()

    def get_group(self, group_id: str) -> dict[str, Any]:
        return self.http.request(
            "GET",
            self._url(f"Groups/{group_id}"),
            headers=self.headers,
        ).json()

    def add_member(self, group_id: str, user_id: str) -> None:
        payload = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {
                    "op": "add",
                    "path": "members",
                    "value": [{"value": user_id}],
                }
            ],
        }
        self.http.request(
            "PATCH",
            self._url(f"Groups/{group_id}"),
            headers=self.headers,
            json=payload,
        )


def validate_okta_domain(value: str) -> str:
    domain = value.strip().lower()
    parsed = urlparse(f"https://{domain}")
    if not domain or parsed.hostname != domain or parsed.path not in ("", "/"):
        raise SyncError(
            "Okta domain must be a hostname such as example.okta.com"
        )
    valid_suffixes = (
        ".okta.com",
        ".okta-emea.com",
        ".oktapreview.com",
    )
    if not domain.endswith(valid_suffixes):
        raise SyncError(
            "Okta domain is outside the expected Okta hostname families"
        )
    return domain


def validate_scim_base_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise SyncError("SCIM base URL must be an HTTPS URL")
    normalized = value.rstrip("/")
    if not normalized.endswith("/scim/v2"):
        raise SyncError("SCIM base URL must end with /scim/v2")
    return normalized


def escape_scim_filter(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def parse_groups(values: Iterable[str]) -> list[str]:
    groups: list[str] = []
    for value in values:
        groups.extend(part.strip() for part in value.split(","))
    deduplicated = list(dict.fromkeys(group for group in groups if group))
    if not deduplicated:
        raise SyncError("at least one non-empty group is required")
    return deduplicated


def make_boto3_session(
    profile: str | None, region: str | None
) -> boto3.Session:
    try:
        return boto3.Session(profile_name=profile, region_name=region)
    except ProfileNotFound as exc:
        raise SyncError(str(exc)) from exc


def get_parameter(ssm: Any, name: str, decrypt: bool) -> str:
    try:
        response = ssm.get_parameter(Name=name, WithDecryption=decrypt)
        value = str(response["Parameter"]["Value"]).strip()
    except (BotoCoreError, ClientError, KeyError) as exc:
        raise SyncError(f"unable to read SSM parameter {name}: {exc}") from exc
    if not value:
        raise SyncError(f"SSM parameter is empty: {name}")
    return value


def ensure_id(value: dict[str, Any], resource_name: str) -> str:
    resource_id = str(value.get("id", "")).strip()
    if not resource_id:
        raise SyncError(f"{resource_name} response did not contain an id")
    return resource_id


def sync_group(
    group_name: str,
    okta: OktaClient,
    scim: ScimClient,
    apply: bool,
    display: IdentifierFormatter,
    counters: Counters,
) -> None:
    okta_group = okta.find_exact_group(group_name)
    okta_group_id = str(okta_group.get("id", "")).strip()
    if not okta_group_id:
        raise SyncError(
            f"Okta group response did not contain an id: {group_name}"
        )

    users = okta.list_group_users(okta_group_id)
    LOG.info(
        "group %s contains %d unique users",
        display(group_name),
        len(users),
    )

    destination_group = scim.find_group(group_name)
    if destination_group is None:
        LOG.warning("would create destination group %s", display(group_name))
        counters.groups_created += 1
        if apply:
            destination_group = scim.create_group(group_name)

    destination_group_id = (
        ensure_id(destination_group, "group") if destination_group else None
    )
    existing_members: set[str] = set()
    if destination_group_id:
        group_state = scim.get_group(destination_group_id)
        existing_members = {
            str(member.get("value"))
            for member in group_state.get("members", [])
            if member.get("value")
        }

    for person in users:
        user = scim.find_user(person.email)
        user_id: str | None = None
        if user is None:
            LOG.warning("would create user %s", display(person.email))
            counters.users_created += 1
            if apply:
                user = scim.create_user(person)
        else:
            counters.unchanged += 1

        if user is not None:
            user_id = ensure_id(user, "user")

        if (
            destination_group_id
            and user_id
            and user_id in existing_members
        ):
            counters.unchanged += 1
            continue

        LOG.warning(
            "would add user %s to group %s",
            display(person.email),
            display(group_name),
        )
        counters.memberships_added += 1
        if apply:
            if not destination_group_id:
                raise SyncError(
                    "destination group id unavailable after group creation"
                )
            if not user_id:
                raise SyncError("user id unavailable after user creation")
            scim.add_member(destination_group_id, user_id)
            existing_members.add(user_id)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Synchronize selected Okta groups into AWS IAM Identity Center. "
            "Dry-run is the default."
        )
    )
    parser.add_argument(
        "--okta-domain",
        default=os.getenv("OKTA_DOMAIN"),
        help="Okta hostname, for example example.okta.com",
    )
    parser.add_argument(
        "--scim-base-url",
        default=os.getenv("AWS_SCIM_BASE_URL"),
        help="IAM Identity Center SCIM URL ending in /scim/v2",
    )
    parser.add_argument(
        "--group",
        action="append",
        default=[],
        help="Exact group name; repeat or provide comma-separated values",
    )
    parser.add_argument(
        "--groups-parameter",
        default=DEFAULT_GROUPS_PARAMETER,
        help=(
            "SSM parameter containing comma-separated groups when --group "
            "is omitted"
        ),
    )
    parser.add_argument(
        "--okta-token-parameter",
        default=DEFAULT_OKTA_TOKEN_PARAMETER,
    )
    parser.add_argument(
        "--scim-token-parameter",
        default=DEFAULT_SCIM_TOKEN_PARAMETER,
    )
    parser.add_argument(
        "--aws-profile",
        default=os.getenv("AWS_PROFILE"),
    )
    parser.add_argument(
        "--aws-region",
        default=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP timeout in seconds",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="perform create and membership operations",
    )
    parser.add_argument(
        "--show-identifiers",
        action="store_true",
        help="show group names and emails in logs instead of hashes",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.okta_domain:
        raise SyncError("--okta-domain or OKTA_DOMAIN is required")
    if not args.scim_base_url:
        raise SyncError("--scim-base-url or AWS_SCIM_BASE_URL is required")
    if args.timeout <= 0:
        raise SyncError("--timeout must be greater than zero")

    session = make_boto3_session(args.aws_profile, args.aws_region)
    ssm = session.client(
        "ssm",
        config=BotoConfig(
            retries={"max_attempts": 5, "mode": "standard"}
        ),
    )

    group_values = args.group or [
        get_parameter(ssm, args.groups_parameter, decrypt=False)
    ]
    groups = parse_groups(group_values)
    okta_token = get_parameter(
        ssm,
        args.okta_token_parameter,
        decrypt=True,
    )
    scim_token = get_parameter(
        ssm,
        args.scim_token_parameter,
        decrypt=True,
    )

    http = HttpClient(timeout=args.timeout)
    okta = OktaClient(args.okta_domain, okta_token, http)
    scim = ScimClient(args.scim_base_url, scim_token, http)
    display = IdentifierFormatter(args.show_identifiers)
    counters = Counters()

    mode = "APPLY" if args.apply else "DRY-RUN"
    LOG.warning("starting in %s mode for %d group(s)", mode, len(groups))
    for group in groups:
        sync_group(
            group,
            okta,
            scim,
            args.apply,
            display,
            counters,
        )

    LOG.warning(
        "%s complete: users=%d groups=%d memberships=%d unchanged=%d",
        mode,
        counters.users_created,
        counters.groups_created,
        counters.memberships_added,
        counters.unchanged,
    )
    if not args.apply:
        LOG.warning(
            "no changes were made; rerun with --apply after reviewing the plan"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SyncError as exc:
        LOG.error("%s", exc)
        raise SystemExit(2) from exc
