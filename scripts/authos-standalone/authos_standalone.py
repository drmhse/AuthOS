#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import base64
import errno
import json
import os
import grp
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit
from datetime import datetime, timedelta, timezone
from pathlib import Path


STATE_VERSION = 2
AUTHOS_USER = "authos"
INSTALL_ROOT = Path("/opt/authos")
INSTALL_BINARY = Path("/usr/local/bin/authos")
APPLY_WRAPPER = Path("/usr/local/bin/authos-apply")
CONFIG_DIR = Path("/etc/authos")
ENV_PATH = CONFIG_DIR / "authos.env"
INSTALL_STATE_PATH = CONFIG_DIR / "install-state.json"
SERVICE_PATH = Path("/etc/systemd/system/authos.service")
APPLY_SERVICE_PATH = Path("/etc/systemd/system/authos-apply.service")
APPLY_PATH_UNIT_PATH = Path("/etc/systemd/system/authos-apply.path")
CADDY_ROOT = Path("/etc/caddy")
CADDY_SITE_DIR = CADDY_ROOT / "sites-enabled"
CADDY_SITE_PATH = CADDY_SITE_DIR / "authos.caddy"
RESERVED_ORG_SLUGS = {
    "api", "www", "mail", "ftp", "admin", "root", "support", "help", "docs", "blog", "news",
    "status", "health", "ping", "cdn", "assets", "static",
}
VALID_SERVICE_TYPES = {"web", "mobile", "desktop", "api"}
ORG_SLUG_RE = re.compile(r"^[a-z0-9_-]{3,50}$")
SERVICE_SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{1,100}$")


def main() -> int:
    parser = argparse.ArgumentParser(description="Install and manage standalone AuthOS")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install", help="Install or upgrade AuthOS")
    install_parser.add_argument("--bundle-dir", required=True)
    install_parser.add_argument("--config", help="Path to a config.json to install")
    install_parser.add_argument("--no-start", action="store_true")

    apply_parser = subparsers.add_parser("apply", help="Render config and restart AuthOS")
    apply_parser.add_argument("--bundle-dir", required=True)
    apply_parser.add_argument("--no-print-link", action="store_true")
    apply_parser.add_argument("--skip-start", action="store_true")

    args = parser.parse_args()

    try:
        if args.command == "install":
            require_root()
            install(
                Path(args.bundle_dir),
                Path(args.config).resolve() if args.config else None,
                args.no_start,
            )
        elif args.command == "apply":
            require_root()
            apply(
                Path(args.bundle_dir),
                print_link=not args.no_print_link,
                start_service=not args.skip_start,
            )
        return 0
    except Exception as exc:
        write_failure_status(str(exc))
        print(f"AuthOS standalone error: {exc}", file=sys.stderr)
        print_failure_recovery_hint()
        return 1


def install(bundle_dir: Path, config_source: Path | None, no_start: bool) -> None:
    stop_existing_service()
    ensure_system_user()
    copy_bundle(bundle_dir)
    current_paths = managed_paths()
    ensure_dir(current_paths["data_dir"], mode=0o700)
    chown_path(current_paths["data_dir"], AUTHOS_USER, AUTHOS_USER)

    desired_config = None
    if config_source:
        desired_config = load_json(config_source)
    elif not current_paths["config_path"].exists():
        example_config = load_json(bundle_dir / "authos.config.example.json")
        desired_config = seed_initial_config(example_config)
    elif not INSTALL_STATE_PATH.exists():
        desired_config = load_json(current_paths["config_path"])

    if desired_config is not None:
        desired_state = build_install_state(desired_config)
        desired_paths = paths_for_data_dir(Path(desired_state["dataDir"]))
        if current_paths != desired_paths:
            relocate_managed_paths(current_paths, desired_paths)
            current_paths = desired_paths
        write_install_state(desired_state)
        config = normalize_config(desired_config, install_state=desired_state)
        write_json(
            current_paths["config_path"],
            config,
            mode=0o640,
            owner=AUTHOS_USER,
            group=AUTHOS_USER,
        )
    else:
        current_state = load_install_state()
        write_install_state(current_state)

    apply(bundle_dir, print_link=True, start_service=not no_start)


def apply(bundle_dir: Path, print_link: bool, start_service: bool) -> None:
    current_paths = managed_paths()
    ensure_dir(current_paths["data_dir"], mode=0o700)
    chown_path(current_paths["data_dir"], AUTHOS_USER, AUTHOS_USER)
    ensure_dir(CONFIG_DIR, mode=0o755)

    install_state = load_install_state()
    config = normalize_config(load_json(current_paths["config_path"]), install_state=install_state)
    validate_managed_config(config)
    paths = current_paths
    ensure_dir(paths["sqlite_dir"], mode=0o700)
    chown_path(paths["sqlite_dir"], AUTHOS_USER, AUTHOS_USER)
    ensure_apply_request_file(paths)

    state = ensure_state(load_json(paths["state_path"], {}))
    original_bootstrap = None
    provisioning_bootstrap = None
    if start_service and config.get("services"):
        original_bootstrap = json.loads(json.dumps(state.get("bootstrap_login") or {}))
        provisioning_bootstrap = new_bootstrap_login(ttl=timedelta(minutes=10))
        state["bootstrap_login"] = provisioning_bootstrap
    write_status(paths["status_path"], {
        "status": "running",
        "message": "Applying AuthOS configuration.",
        "updated_at": now_rfc3339(),
    })

    env_values = build_env(config, state, paths)
    write_json(
        paths["config_path"], config, mode=0o640, owner=AUTHOS_USER, group=AUTHOS_USER
    )
    write_json(
        paths["state_path"], state, mode=0o640, owner=AUTHOS_USER, group=AUTHOS_USER
    )
    write_env(ENV_PATH, env_values, mode=0o640, owner="root", group=AUTHOS_USER)
    chown_path(paths["status_path"], AUTHOS_USER, AUTHOS_USER)
    chown_path(paths["request_path"], AUTHOS_USER, AUTHOS_USER)

    install_apply_wrapper()
    write_systemd_unit(config, paths)
    write_apply_service_unit(paths)
    write_apply_path_unit(paths)

    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "authos.service"])
    run(["systemctl", "enable", "authos-apply.path"])
    run(["systemctl", "restart", "authos-apply.path"])
    remove_legacy_sudoers()
    configure_caddy(config, paths)

    provision_report = []

    if start_service:
        try:
            run(["systemctl", "restart", "authos.service"])
            wait_for_systemd("authos.service")
            wait_for_http_readiness(config["deployment"]["baseUrl"])
            provision_report = provision_resources(
                config,
                state,
                paths,
                bootstrap_token=provisioning_bootstrap["token"] if provisioning_bootstrap else None,
            )
        finally:
            if original_bootstrap is not None:
                state["bootstrap_login"] = original_bootstrap
                persist_state(paths, state)

    login_url = bootstrap_login_url(config, state)
    status_payload = {
        "status": "success",
        "message": "AuthOS configuration applied successfully.",
        "updated_at": now_rfc3339(),
        "public_url": config["deployment"]["platformBaseUrl"],
        "config_path": str(paths["config_path"]),
        "login_url": login_url,
    }
    if provision_report:
        status_payload["provisioning"] = provision_report
    write_status(paths["status_path"], status_payload)

    if print_link:
        print("")
        print("AuthOS standalone apply complete")
        print(f"Config: {paths['config_path']}")
        print(f"State: {paths['state_path']}")
        print(f"Status: {paths['status_path']}")
        print(f"Public URL: {config['deployment']['platformBaseUrl']}")
        if login_url:
            print(f"Bootstrap login link: {login_url}")
        print("")


def managed_paths() -> dict:
    data_dir = managed_data_dir()
    return paths_for_data_dir(data_dir)


def paths_for_data_dir(data_dir: Path) -> dict:
    return {
        "data_dir": data_dir,
        "sqlite_dir": data_dir / "data",
        "config_path": data_dir / "config.json",
        "state_path": data_dir / "state.json",
        "status_path": data_dir / "status.json",
        "request_path": data_dir / "apply-request.json",
    }


def seed_initial_config(example: dict) -> dict:
    config = json.loads(json.dumps(example))
    ip_address = detect_primary_ip()
    api_port = int(config.get("deployment", {}).get("apiPort") or 3001)
    base_url = f"http://{ip_address}:{api_port}"

    deployment = config.setdefault("deployment", {})
    deployment["backend"] = "sqlite"
    deployment["buildLocalImage"] = False
    deployment["image"] = ""
    deployment["apiPort"] = api_port
    deployment["baseUrl"] = base_url
    deployment["platformBaseUrl"] = base_url
    deployment["fullWebClientBaseUrl"] = ""
    deployment["trustProxyHeaders"] = False
    deployment["trustedProxyIps"] = ""
    deployment["disableRateLimiting"] = False
    deployment["geoipDisabled"] = True
    deployment["jobProcessorIntervalSecs"] = 10
    deployment["jobProcessorBatchSize"] = 10

    smtp = config.setdefault("smtp", {})
    smtp["mode"] = "disabled"
    smtp["host"] = ""
    smtp["port"] = 1025
    smtp["username"] = ""
    smtp["password"] = ""
    smtp["fromEmail"] = smtp.get("fromEmail") or "noreply@authos.local"
    smtp["fromName"] = smtp.get("fromName") or "AuthOS"

    services = config.get("services") or []
    if services:
        for service in services:
            redirect_uris = service.get("redirectUris") or []
            if redirect_uris:
                service["redirectUris"] = [f"{base_url}/callback"]

    config.setdefault("standalone", {
        "dataDir": "/var/lib/authos",
    })
    config.setdefault("caddy", {
        "enabled": False,
        "install": False,
        "domain": "",
        "email": "",
        "tls": "auto",
    })
    return config


def normalize_config(config: dict, install_state: dict | None = None) -> dict:
    if not isinstance(config, dict):
        raise RuntimeError("Managed config must be a JSON object")

    deployment = config.setdefault("deployment", {})
    previous_base_url = normalize_url_value(deployment.get("baseUrl"))
    previous_platform_base_url = normalize_url_value(deployment.get("platformBaseUrl"))
    previous_public_urls = {value for value in (previous_base_url, previous_platform_base_url) if value}
    if deployment.get("backend", "sqlite") != "sqlite":
        raise RuntimeError("Standalone AuthOS currently supports deployment.backend=sqlite only")

    standalone = config.setdefault("standalone", {})
    install_state = install_state or load_install_state()
    standalone["dataDir"] = install_state["dataDir"]

    caddy = config.setdefault("caddy", {})
    caddy.setdefault("enabled", False)
    caddy["install"] = bool(install_state.get("allowCaddyInstall", False))
    caddy.setdefault("domain", "")
    caddy.setdefault("email", "")
    caddy.setdefault("tls", "auto")

    deployment["apiPort"] = int(deployment.get("apiPort") or 3001)

    if caddy.get("enabled"):
        domain = caddy.get("domain", "").strip()
        if not domain:
            raise RuntimeError("caddy.domain must be set when caddy.enabled=true")
        tls_mode = caddy.get("tls", "auto")
        if tls_mode not in {"auto", "internal", "disabled"}:
            raise RuntimeError("caddy.tls must be one of auto, internal, or disabled")
        scheme = "http" if tls_mode == "disabled" else "https"
        public_url = f"{scheme}://{domain}"
        deployment["baseUrl"] = public_url
        deployment["platformBaseUrl"] = public_url
        deployment["trustProxyHeaders"] = True
        deployment["trustedProxyIps"] = deployment.get("trustedProxyIps") or "127.0.0.1,::1"
        deployment["serverHost"] = "127.0.0.1"
    else:
        base_url = str(deployment.get("baseUrl") or "").strip()
        if not base_url:
            base_url = f"http://{detect_primary_ip()}:{deployment['apiPort']}"
            deployment["baseUrl"] = base_url
        deployment["platformBaseUrl"] = str(deployment.get("platformBaseUrl") or base_url).rstrip("/")
        deployment["baseUrl"] = str(deployment["baseUrl"]).rstrip("/")
        deployment["trustProxyHeaders"] = bool(deployment.get("trustProxyHeaders"))
        deployment["serverHost"] = deployment.get("serverHost") or "0.0.0.0"

    deployment.setdefault("rustLog", "info")
    deployment.setdefault("fullWebClientBaseUrl", "")
    deployment.setdefault("disableRateLimiting", False)
    deployment.setdefault("geoipDisabled", True)
    deployment.setdefault("jobProcessorIntervalSecs", 10)
    deployment.setdefault("jobProcessorBatchSize", 10)
    deployment.setdefault("maxMindLicenseKey", "")

    platform_owner = config.setdefault("platformOwner", {})
    platform_owner.setdefault("email", "admin@example.com")
    platform_owner.setdefault("password", "")

    billing = config.setdefault("billing", {})
    billing.setdefault("provider", "none")
    billing.setdefault("stripeSecretKey", "")
    billing.setdefault("stripeWebhookSecret", "")
    billing.setdefault("stripeWebhookTestMode", True)
    billing.setdefault("stripeApiBaseUrl", "")
    billing.setdefault("polarApiKey", "")
    billing.setdefault("polarWebhookSecret", "")
    billing.setdefault("polarApiBaseUrl", "")
    if billing["provider"] not in {"none", "stripe", "polar"}:
        raise RuntimeError("billing.provider must be one of none, stripe, or polar")
    if billing["provider"] == "stripe":
        if not str(billing.get("stripeSecretKey") or "").strip():
            raise RuntimeError("billing.stripeSecretKey is required when billing.provider=stripe")
        if not str(billing.get("stripeWebhookSecret") or "").strip():
            raise RuntimeError("billing.stripeWebhookSecret is required when billing.provider=stripe")
    if billing["provider"] == "polar":
        if not str(billing.get("polarApiKey") or "").strip():
            raise RuntimeError("billing.polarApiKey is required when billing.provider=polar")
        if not str(billing.get("polarWebhookSecret") or "").strip():
            raise RuntimeError("billing.polarWebhookSecret is required when billing.provider=polar")

    smtp = config.setdefault("smtp", {})
    smtp.setdefault("mode", "disabled")
    smtp.setdefault("fromEmail", "noreply@authos.local")
    smtp.setdefault("fromName", "AuthOS")
    smtp.setdefault("host", "")
    smtp.setdefault("port", 1025)
    smtp.setdefault("username", "")
    smtp.setdefault("password", "")

    oauth = config.setdefault("oauth", {})
    for provider in ("github", "google", "microsoft"):
        oauth.setdefault(provider, {
            "clientId": "",
            "clientSecret": "",
            "authUrl": "",
            "tokenUrl": "",
            "userApiUrl": "",
        })
        oauth[provider].setdefault("clientId", "")
        oauth[provider].setdefault("clientSecret", "")
        oauth[provider].setdefault("authUrl", "")
        oauth[provider].setdefault("tokenUrl", "")
        oauth[provider].setdefault("userApiUrl", "")
        oauth[provider]["redirectUri"] = admin_oauth_redirect_uri(deployment["baseUrl"], provider)

    rewrite_managed_service_redirects(
        config.get("services") or [],
        previous_public_urls,
        deployment["baseUrl"],
    )

    return config


def validate_managed_config(config: dict) -> None:
    services = config.get("services") or []
    if not isinstance(services, list):
        raise RuntimeError("services must be an array")

    seen_services: set[tuple[str, str]] = set()
    for index, service in enumerate(services):
        if not isinstance(service, dict):
            raise RuntimeError(f"services[{index}] must be an object")

        org_slug = str(service.get("org") or "").strip()
        if not org_slug:
            raise RuntimeError(f"services[{index}].org is required")
        if not ORG_SLUG_RE.fullmatch(org_slug):
            raise RuntimeError(
                f"services[{index}].org must be 3-50 characters of lowercase letters, digits, hyphens, or underscores"
            )
        if org_slug in RESERVED_ORG_SLUGS:
            raise RuntimeError(
                f"services[{index}].org '{org_slug}' is reserved; choose another organization slug"
            )

        service_slug = str(service.get("service") or "").strip()
        if not service_slug:
            raise RuntimeError(f"services[{index}].service is required")
        if not SERVICE_SLUG_RE.fullmatch(service_slug):
            raise RuntimeError(
                f"services[{index}].service must be 1-100 characters of letters, digits, hyphens, or underscores"
            )

        service_type = str(service.get("type") or "web").strip()
        if service_type not in VALID_SERVICE_TYPES:
            raise RuntimeError(
                f"services[{index}].type must be one of: {', '.join(sorted(VALID_SERVICE_TYPES))}"
            )

        service_key = (org_slug, service_slug)
        if service_key in seen_services:
            raise RuntimeError(
                f"services[{index}] duplicates organization/service pair '{org_slug}/{service_slug}'"
            )
        seen_services.add(service_key)


def ensure_state(state: dict) -> dict:
    if state.get("version") != STATE_VERSION:
        state = {}

    jwt = state.get("jwt") or generate_jwt_keys()
    bootstrap_login = state.get("bootstrap_login") or {}
    if not bootstrap_login.get("token"):
        bootstrap_login = new_bootstrap_login(ttl=timedelta(days=7))

    return {
        "version": STATE_VERSION,
        "updatedAt": now_rfc3339(),
        "jwt": jwt,
        "encryptionKey": state.get("encryptionKey") or secrets.token_hex(32),
        "deviceTrustSecret": state.get("deviceTrustSecret") or secrets.token_hex(32),
        "bootstrap_login": bootstrap_login,
    }


def new_bootstrap_login(ttl: timedelta) -> dict:
    return {
        "token": secrets.token_urlsafe(32),
        "created_at": now_rfc3339(),
        "expires_at": (datetime.now(timezone.utc) + ttl).isoformat(),
        "used_at": None,
    }


def generate_jwt_keys() -> dict:
    if shutil.which("openssl") is None:
        raise RuntimeError("openssl is required to generate JWT keys")

    with tempfile.TemporaryDirectory() as temp_dir:
        private_key_path = Path(temp_dir) / "jwt-private.pem"
        public_key_path = Path(temp_dir) / "jwt-public.pem"
        run([
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-out",
            str(private_key_path),
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        run([
            "openssl",
            "rsa",
            "-pubout",
            "-in",
            str(private_key_path),
            "-out",
            str(public_key_path),
        ])
        return {
            "privateKeyBase64": base64.b64encode(private_key_path.read_bytes()).decode("utf-8"),
            "publicKeyBase64": base64.b64encode(public_key_path.read_bytes()).decode("utf-8"),
            "kid": f"authos-{secrets.token_hex(8)}",
        }


def build_env(config: dict, state: dict, paths: dict) -> dict:
    deployment = config["deployment"]
    billing = config["billing"]
    smtp = config["smtp"]
    oauth = config["oauth"]

    env = {
        "DATABASE_URL": f"sqlite://{paths['sqlite_dir'] / 'authos.db'}?mode=rwc",
        "RUST_LOG": deployment["rustLog"],
        "JWT_PRIVATE_KEY_BASE64": state["jwt"]["privateKeyBase64"],
        "JWT_PUBLIC_KEY_BASE64": state["jwt"]["publicKeyBase64"],
        "JWT_KID": state["jwt"]["kid"],
        "JWT_PREVIOUS_PUBLIC_KEYS_JSON": json.dumps(
            state["jwt"].get("previousPublicKeys", {}), separators=(",", ":")
        ),
        "JWT_EXPIRATION_HOURS": "24",
        "BILLING_PROVIDER": billing["provider"],
        "SERVER_HOST": deployment["serverHost"],
        "SERVER_PORT": str(deployment["apiPort"]),
        "BASE_URL": deployment["baseUrl"],
        "PLATFORM_BASE_URL": deployment["platformBaseUrl"],
        "PLATFORM_OWNER_EMAIL": config["platformOwner"]["email"],
        "ENCRYPTION_KEY": state["encryptionKey"],
        "DEVICE_TRUST_SECRET": state["deviceTrustSecret"],
        "DISABLE_RATE_LIMITING": str(bool(deployment["disableRateLimiting"])).lower(),
        "TRUST_PROXY_HEADERS": str(bool(deployment["trustProxyHeaders"])).lower(),
        "TRUSTED_PROXY_IPS": deployment.get("trustedProxyIps", ""),
        "GEOIP_DISABLED": str(bool(deployment["geoipDisabled"])).lower(),
        "MAXMIND_LICENSE_KEY": deployment.get("maxMindLicenseKey", ""),
        "JOB_PROCESSOR_INTERVAL_SECS": str(int(deployment["jobProcessorIntervalSecs"])),
        "JOB_PROCESSOR_BATCH_SIZE": str(int(deployment["jobProcessorBatchSize"])),
        "AUTHOS_MANAGED_CONFIG_PATH": str(paths["config_path"]),
        "AUTHOS_MANAGED_STATE_PATH": str(paths["state_path"]),
        "AUTHOS_MANAGED_STATUS_PATH": str(paths["status_path"]),
        "AUTHOS_MANAGED_REQUEST_PATH": str(paths["request_path"]),
    }

    add_if(env, "PLATFORM_OWNER_PASSWORD", config["platformOwner"].get("password"))

    if deployment.get("fullWebClientBaseUrl"):
        env["FULL_WEB_CLIENT_BASE_URL"] = deployment["fullWebClientBaseUrl"]
    if billing.get("provider") == "stripe":
        add_if(env, "STRIPE_SECRET_KEY", billing.get("stripeSecretKey"))
        add_if(env, "STRIPE_WEBHOOK_SECRET", billing.get("stripeWebhookSecret"))
    if billing.get("stripeApiBaseUrl"):
        env["STRIPE_API_BASE_URL"] = billing["stripeApiBaseUrl"]
    if billing.get("polarApiKey"):
        env["POLAR_API_KEY"] = billing["polarApiKey"]
    if billing.get("polarWebhookSecret"):
        env["POLAR_WEBHOOK_SECRET"] = billing["polarWebhookSecret"]
    if billing.get("polarApiBaseUrl"):
        env["POLAR_API_BASE_URL"] = billing["polarApiBaseUrl"]

    for provider, prefix in (("github", "PLATFORM_GITHUB"), ("google", "PLATFORM_GOOGLE"), ("microsoft", "PLATFORM_MICROSOFT")):
        cfg = oauth[provider]
        add_if(env, f"{prefix}_CLIENT_ID", cfg.get("clientId"))
        add_if(env, f"{prefix}_CLIENT_SECRET", cfg.get("clientSecret"))
        add_if(env, f"{prefix}_REDIRECT_URI", cfg.get("redirectUri"))
        add_if(env, f"{prefix}_AUTH_URL", cfg.get("authUrl"))
        add_if(env, f"{prefix}_TOKEN_URL", cfg.get("tokenUrl"))
        add_if(env, f"{prefix}_USER_API_URL", cfg.get("userApiUrl"))

    if smtp.get("mode") != "disabled":
        add_if(env, "SMTP_HOST", smtp.get("host"))
        add_if(env, "SMTP_PORT", str(smtp.get("port") or 1025))
        add_if(env, "SMTP_USERNAME", smtp.get("username"))
        add_if(env, "SMTP_PASSWORD", smtp.get("password"))
        add_if(env, "SMTP_FROM_EMAIL", smtp.get("fromEmail"))
        add_if(env, "SMTP_FROM_NAME", smtp.get("fromName"))

    return env


def provision_resources(config: dict, state: dict, paths: dict, bootstrap_token: str | None = None) -> list[dict]:
    services = config.get("services") or []
    if not services:
        return []

    base_url = config["deployment"]["baseUrl"]
    token = acquire_management_token(base_url, state, paths, bootstrap_token=bootstrap_token)
    client = StandaloneAuthOsClient(base_url, token)
    report = []

    try:
        for service in services:
            try:
                organization_status = ensure_organization(client, service["org"], service.get("orgName") or service["org"])
                service_result = ensure_service(client, service)
                api_keys = []
                for api_key in service.get("apiKeys") or []:
                    api_keys.append(ensure_api_key(client, paths, service, api_key))
                report.append({
                    "org": service["org"],
                    "organizationStatus": organization_status,
                    "service": service["service"],
                    "serviceStatus": service_result["status"],
                    "clientId": service_result["clientId"],
                    "apiKeys": api_keys,
                })
            except Exception as exc:
                raise RuntimeError(
                    f"Provisioning failed for services entry '{service.get('org', '?')}/{service.get('service', '?')}': {exc}"
                ) from exc
    finally:
        # Do not leave the bootstrap provisioning session behind after the
        # installer has finished using it.
        try:
            client.request("/api/auth/logout", method="POST")
        except Exception:
            pass

    return report


def acquire_management_token(base_url: str, state: dict, paths: dict, bootstrap_token: str | None = None) -> str:
    if not bootstrap_token:
        bootstrap_login = new_bootstrap_login(ttl=timedelta(minutes=10))
        state["bootstrap_login"] = bootstrap_login
        persist_state(paths, state)
        bootstrap_token = bootstrap_login["token"]
    else:
        current_state = load_json(paths["state_path"], {})
        current_token = (
            current_state.get("bootstrap_login", {})
            .get("token")
            if isinstance(current_state, dict)
            else None
        )
        if current_token:
            bootstrap_token = current_token

    response = request_json(
        f"{base_url}/api/public/bootstrap-login",
        method="POST",
        body={"token": bootstrap_token},
    )
    access_token = str(response.get("access_token") or "").strip()
    if not access_token:
        raise RuntimeError("Bootstrap login did not return an access token")
    return access_token


class StandaloneAuthOsClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(self, pathname: str, method: str = "GET", body=None):
        headers = {
            "accept": "application/json",
            "authorization": f"Bearer {self.token}",
        }
        if body is not None:
            headers["content-type"] = "application/json"
        return request_json(f"{self.base_url}{pathname}", method=method, headers=headers, body=body)


def ensure_organization(client: "StandaloneAuthOsClient", org_slug: str, org_name: str) -> str:
    organization = None
    status = "unchanged"

    try:
        response = client.request(f"/api/organizations/{quote(org_slug)}")
        organization = response.get("organization") or response
    except StandaloneHttpError as error:
        if error.status != 404:
            raise

    if not organization:
        response = client.request(
            "/api/organizations",
            method="POST",
            body={"slug": org_slug, "name": org_name},
        )
        organization = response.get("organization") or response
        status = "created"

    org_status = organization.get("status")
    org_id = organization.get("id")

    if org_status == "pending" and org_id:
        client.request(
            f"/api/platform/organizations/{quote(org_id)}/approve",
            method="POST",
            body={"tier_id": organization.get("tier_id") or "tier_free"},
        )
        return "created+approved" if status == "created" else "approved"

    if org_status == "suspended" and org_id:
        client.request(
            f"/api/platform/organizations/{quote(org_id)}/activate",
            method="POST",
            body={},
        )
        return "activated"

    return status


def ensure_service(client: "StandaloneAuthOsClient", service: dict) -> dict:
    existing = find_service(client, service["org"], service["service"])
    desired = {
        "slug": service["service"],
        "name": service.get("name") or service["service"],
        "service_type": service.get("type") or "web",
        "redirect_uris": service.get("redirectUris") or [],
        "github_scopes": service.get("githubScopes") or [],
    }

    if not existing:
        response = client.request(
            f"/api/organizations/{quote(service['org'])}/services",
            method="POST",
            body=desired,
        )
        created = response.get("service") or response
        return {
            "status": "created",
            "clientId": created.get("client_id") or "",
        }

    needs_update = (
        existing.get("name") != desired["name"]
        or existing.get("service_type") != desired["service_type"]
        or not same_string_set(existing.get("redirect_uris") or [], desired["redirect_uris"])
        or not same_string_set(existing.get("github_scopes") or [], desired["github_scopes"])
    )
    if not needs_update:
        return {
            "status": "unchanged",
            "clientId": existing.get("client_id") or "",
        }

    updated = client.request(
        f"/api/organizations/{quote(service['org'])}/services/{quote(service['service'])}",
        method="PATCH",
        body=desired,
    )
    return {
        "status": "updated",
        "clientId": updated.get("client_id") or existing.get("client_id") or "",
    }


def find_service(client: "StandaloneAuthOsClient", org_slug: str, service_slug: str):
    response = client.request(f"/api/organizations/{quote(org_slug)}/services")
    for candidate in response.get("services") or []:
        if candidate.get("slug") == service_slug:
            return candidate
    return None


def ensure_api_key(client: "StandaloneAuthOsClient", paths: dict, service: dict, api_key: dict) -> dict:
    name = str(api_key.get("name") or "").strip()
    if not name:
        raise RuntimeError(f"Service {service['org']}/{service['service']} has an apiKeys[] entry without name")

    list_response = client.request(
        f"/api/organizations/{quote(service['org'])}/services/{quote(service['service'])}/api-keys"
    )
    for candidate in list_response.get("api_keys") or []:
        if candidate.get("name") == name and not api_key.get("forceNew"):
            return {
                "name": name,
                "status": "existing",
                "prefix": candidate.get("prefix") or "",
            }

    write_to = str(api_key.get("writeTo") or "")
    if not write_to:
        raise RuntimeError(
            f"API key {name} needs writeTo because new API key secrets are shown once"
        )

    # Open and retain the destination directory before creating a one-time
    # secret. Managed configuration is writable through the lite client while
    # this apply process runs as root, so every component is opened without
    # following symlinks and the directory identity is rechecked before write.
    target = resolve_output_path(paths["data_dir"], write_to)
    parent_fd, filename, parent_identity = open_managed_output_parent(
        paths["data_dir"], write_to, owner=AUTHOS_USER, group=AUTHOS_USER
    )
    try:
        target_identity = managed_output_target_identity(parent_fd, filename)
        created = client.request(
            f"/api/organizations/{quote(service['org'])}/services/{quote(service['service'])}/api-keys",
            method="POST",
            body={
                "name": name,
                "permissions": api_key.get("permissions") or [],
            },
        )
        assert_managed_output_parent_unchanged(
            paths["data_dir"], write_to, parent_identity
        )
        atomic_write_text_at(
            parent_fd,
            filename,
            f"AUTHOS_API_KEY={created['key']}\n",
            mode=0o600,
            owner=AUTHOS_USER,
            group=AUTHOS_USER,
            expected_identity=target_identity,
        )
    finally:
        os.close(parent_fd)
    return {
        "name": name,
        "status": "created",
        "prefix": created.get("prefix") or "",
        "writtenTo": str(target),
    }


def resolve_output_path(data_dir: Path, write_to: str) -> Path:
    parts = validate_managed_output_name(write_to)
    if not data_dir.is_absolute():
        raise RuntimeError("standalone.dataDir must be an absolute path")
    return data_dir.joinpath(*parts)


def validate_managed_output_name(write_to: str) -> tuple[str, ...]:
    if not write_to or write_to != write_to.strip():
        raise RuntimeError("apiKeys[].writeTo must be a non-empty relative path")
    if any(ord(character) < 32 or ord(character) == 127 for character in write_to):
        raise RuntimeError("apiKeys[].writeTo must not contain control characters")
    target = Path(write_to)
    if target.is_absolute():
        raise RuntimeError("apiKeys[].writeTo must be relative to standalone.dataDir")
    raw_parts = write_to.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise RuntimeError(
            "apiKeys[].writeTo must contain only non-empty child path components"
        )
    return tuple(raw_parts)


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_directory_tree_nofollow(
    path: Path,
    *,
    create: bool,
    owner: str | None = None,
    group: str | None = None,
) -> int:
    if not path.is_absolute():
        raise RuntimeError("managed directory must be absolute")
    current_fd = os.open("/", _directory_open_flags())
    try:
        for component in path.parts[1:]:
            if component in {"", ".", ".."} or any(
                ord(character) < 32 or ord(character) == 127 for character in component
            ):
                raise RuntimeError("managed directory contains an unsafe path component")
            try:
                next_fd = os.open(component, _directory_open_flags(), dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise RuntimeError("managed output parent changed during API-key creation")
                os.mkdir(component, mode=0o700, dir_fd=current_fd)
                next_fd = os.open(component, _directory_open_flags(), dir_fd=current_fd)
                uid = pwd.getpwnam(owner).pw_uid if owner else os.geteuid()
                gid = grp.getgrnam(group).gr_gid if group else os.getegid()
                os.fchown(next_fd, uid, gid)
                os.fchmod(next_fd, 0o700)
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise RuntimeError(
                        "managed output path contains a symlink or non-directory component"
                    ) from error
                raise
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def open_managed_output_parent(
    data_dir: Path,
    write_to: str,
    *,
    owner: str | None = None,
    group: str | None = None,
) -> tuple[int, str, tuple[int, int]]:
    parts = validate_managed_output_name(write_to)
    parent = data_dir.joinpath(*parts[:-1])
    parent_fd = _open_directory_tree_nofollow(
        parent, create=True, owner=owner, group=group
    )
    stat_result = os.fstat(parent_fd)
    return parent_fd, parts[-1], (stat_result.st_dev, stat_result.st_ino)


def assert_managed_output_parent_unchanged(
    data_dir: Path, write_to: str, expected: tuple[int, int]
) -> None:
    parts = validate_managed_output_name(write_to)
    check_fd = _open_directory_tree_nofollow(
        data_dir.joinpath(*parts[:-1]), create=False
    )
    try:
        actual_stat = os.fstat(check_fd)
        actual = (actual_stat.st_dev, actual_stat.st_ino)
        if actual != expected:
            raise RuntimeError("managed output parent changed during API-key creation")
    finally:
        os.close(check_fd)


def managed_output_target_identity(
    parent_fd: int, filename: str
) -> tuple[int, int] | None:
    try:
        target = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(target.st_mode):
        raise RuntimeError("managed output target must be a regular file")
    if target.st_nlink != 1:
        raise RuntimeError("managed output target must not be hard-linked")
    return target.st_dev, target.st_ino


def atomic_write_text_at(
    parent_fd: int,
    filename: str,
    payload: str,
    *,
    mode: int,
    owner: str | None = None,
    group: str | None = None,
    expected_identity: tuple[int, int] | None | object = Ellipsis,
) -> None:
    before_identity = managed_output_target_identity(parent_fd, filename)
    if expected_identity is not Ellipsis and before_identity != expected_identity:
        raise RuntimeError("managed output target changed before atomic write")

    temporary_name = f".{filename}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(temporary_name, flags, mode, dir_fd=parent_fd)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(payload.encode("utf-8"))
            handle.flush()
            uid = pwd.getpwnam(owner).pw_uid if owner else os.geteuid()
            gid = grp.getgrnam(group).gr_gid if group else os.getegid()
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            os.fsync(fd)

        after = None
        try:
            after = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        after_identity = None if after is None else (after.st_dev, after.st_ino)
        if before_identity != after_identity:
            raise RuntimeError("managed output target changed during atomic write")
        if after is not None and (
            not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
        ):
            raise RuntimeError("managed output target became unsafe during atomic write")

        os.replace(
            temporary_name,
            filename,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    finally:
        os.close(fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass


def same_string_set(left: list[str], right: list[str]) -> bool:
    if len(left) != len(right):
        return False
    return set(left) == set(right)


def rewrite_managed_service_redirects(services: list[dict], previous_public_urls: set[str], base_url: str) -> None:
    for service in services:
        redirect_uris = service.get("redirectUris")
        if not isinstance(redirect_uris, list):
            continue

        rewritten = []
        for redirect_uri in redirect_uris:
            normalized = normalize_url_value(redirect_uri)
            if normalized and should_follow_authos_callback(normalized, previous_public_urls):
                rewritten.append(f"{base_url}/callback")
            else:
                rewritten.append(redirect_uri)
        service["redirectUris"] = rewritten


def should_follow_authos_callback(url: str, previous_public_urls: set[str]) -> bool:
    try:
        parsed = urlsplit(url)
    except Exception:
        return False

    if parsed.query or parsed.fragment or parsed.path.rstrip("/") != "/callback":
        return False

    origin = normalize_url_value(f"{parsed.scheme}://{parsed.netloc}")
    return bool(origin and origin in previous_public_urls)


def admin_oauth_redirect_uri(base_url: str, provider: str) -> str:
    return f"{normalize_url_value(base_url)}/auth/admin/{provider}/callback"


def normalize_url_value(value) -> str:
    return str(value or "").strip().rstrip("/")


def configure_caddy(config: dict, paths: dict) -> None:
    caddy = config["caddy"]

    if not caddy.get("enabled"):
        if CADDY_SITE_PATH.exists():
            CADDY_SITE_PATH.unlink()
            if shutil.which("systemctl") and shutil.which("caddy"):
                run(["systemctl", "reload", "caddy.service"], check=False)
        return

    if shutil.which("caddy") is None:
        if not caddy.get("install"):
            raise RuntimeError("Caddy is enabled in config.json but caddy is not installed")
        install_caddy()

    ensure_dir(CADDY_SITE_DIR, mode=0o755)
    ensure_caddy_main_file()
    atomic_write_text(
        CADDY_SITE_PATH,
        render_caddy_site(config, paths),
        mode=0o644,
        owner="root",
        group="root",
    )
    run(["caddy", "validate", "--config", str(CADDY_ROOT / "Caddyfile")])
    run(["systemctl", "enable", "caddy.service"])
    run(["systemctl", "restart", "caddy.service"])
    wait_for_systemd("caddy.service")


def install_caddy() -> None:
    if shutil.which("apt-get") is None:
        raise RuntimeError("Automatic Caddy installation requires apt-get")
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "caddy"])


def ensure_caddy_main_file() -> None:
    ensure_dir(CADDY_ROOT, mode=0o755)
    caddyfile = CADDY_ROOT / "Caddyfile"
    if not caddyfile.exists():
        atomic_write_text(
            caddyfile,
            "import /etc/caddy/sites-enabled/*.caddy\n",
            mode=0o644,
            owner="root",
            group="root",
        )
        return

    content = caddyfile.read_text(encoding="utf-8")
    include_line = "import /etc/caddy/sites-enabled/*.caddy"
    if include_line not in content:
        content = content.rstrip() + "\n\n" + include_line + "\n"
        atomic_write_text(
            caddyfile,
            content,
            mode=stat.S_IMODE(caddyfile.stat().st_mode),
        )


def render_caddy_site(config: dict, paths: dict) -> str:
    caddy = config["caddy"]
    host = caddy["domain"]
    admin_email = caddy.get("email", "").strip()
    tls_mode = caddy.get("tls", "auto")
    admin_block = f"{{\n  email {admin_email}\n}}\n\n" if admin_email else ""
    site_label = f"http://{host}" if tls_mode == "disabled" else host
    tls_directive = "  tls internal\n" if tls_mode == "internal" else ""

    return (
        f"{admin_block}"
        f"{site_label} {{\n"
        f"  encode zstd gzip\n"
        f"{tls_directive}"
        f"  reverse_proxy 127.0.0.1:{config['deployment']['apiPort']}\n"
        f"}}\n"
    )


def write_systemd_unit(config: dict, paths: dict) -> None:
    service_text = f"""[Unit]
Description=AuthOS standalone service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={AUTHOS_USER}
Group={AUTHOS_USER}
WorkingDirectory={paths['data_dir']}
EnvironmentFile={ENV_PATH}
ExecStart={INSTALL_BINARY}
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths={paths['data_dir']}
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""
    atomic_write_text(
        SERVICE_PATH, service_text, mode=0o644, owner="root", group="root"
    )


def install_apply_wrapper() -> None:
    wrapper = f"""#!/usr/bin/env bash
set -euo pipefail
exec python3 {INSTALL_ROOT / 'standalone' / 'authos_standalone.py'} "$@"
"""
    atomic_write_text(
        APPLY_WRAPPER, wrapper, mode=0o755, owner="root", group="root"
    )


def write_apply_service_unit(paths: dict) -> None:
    service_text = f"""[Unit]
Description=AuthOS standalone apply worker

[Service]
Type=oneshot
ExecStart={APPLY_WRAPPER} apply --bundle-dir {INSTALL_ROOT} --no-print-link
"""
    atomic_write_text(
        APPLY_SERVICE_PATH, service_text, mode=0o644, owner="root", group="root"
    )


def write_apply_path_unit(paths: dict) -> None:
    path_text = f"""[Unit]
Description=Watch AuthOS apply requests

[Path]
PathModified={paths['request_path']}

[Install]
WantedBy=multi-user.target
"""
    atomic_write_text(
        APPLY_PATH_UNIT_PATH, path_text, mode=0o644, owner="root", group="root"
    )


def copy_bundle(bundle_dir: Path) -> None:
    ensure_dir(INSTALL_ROOT, mode=0o755)
    ensure_dir(INSTALL_ROOT / "standalone", mode=0o755)

    atomic_copy_file(bundle_dir / "authos", INSTALL_BINARY, mode=0o755, owner="root", group="root")
    atomic_copy_file(
        bundle_dir / "authos.config.example.json",
        INSTALL_ROOT / "authos.config.example.json",
        mode=0o644,
        owner="root",
        group="root",
    )
    atomic_copy_file(
        bundle_dir / "standalone" / "authos_standalone.py",
        INSTALL_ROOT / "standalone" / "authos_standalone.py",
        mode=0o755,
        owner="root",
        group="root",
    )
    for notice in ("LICENSE", "AGPL-3.0.txt", "README.txt"):
        atomic_copy_file(
            bundle_dir / notice,
            INSTALL_ROOT / notice,
            mode=0o644,
            owner="root",
            group="root",
        )


def managed_data_dir() -> Path:
    raw_value = load_install_state().get("dataDir", "/var/lib/authos")
    data_dir = Path(str(raw_value).strip() or "/var/lib/authos")
    if not data_dir.is_absolute():
        raise RuntimeError("standalone.dataDir must be an absolute path")
    return data_dir


def load_install_state() -> dict:
    if not INSTALL_STATE_PATH.exists():
        return {"dataDir": "/var/lib/authos", "allowCaddyInstall": False}

    try:
        payload = load_json(INSTALL_STATE_PATH, {})
    except Exception:
        return {"dataDir": "/var/lib/authos", "allowCaddyInstall": False}

    if not isinstance(payload, dict):
        return {"dataDir": "/var/lib/authos", "allowCaddyInstall": False}

    return {
        "dataDir": str(payload.get("dataDir") or "/var/lib/authos"),
        "allowCaddyInstall": bool(payload.get("allowCaddyInstall", False)),
    }


def configured_data_dir(config: dict) -> Path:
    raw_value = config.get("standalone", {}).get("dataDir", "/var/lib/authos")
    data_dir = Path(str(raw_value).strip() or "/var/lib/authos")
    if not data_dir.is_absolute():
        raise RuntimeError("standalone.dataDir must be an absolute path")
    return data_dir


def build_install_state(config: dict) -> dict:
    return {
        "dataDir": str(configured_data_dir(config)),
        "allowCaddyInstall": bool(config.get("caddy", {}).get("install", False)),
    }


def write_install_state(payload: dict) -> None:
    ensure_dir(CONFIG_DIR, mode=0o755)
    write_json(
        INSTALL_STATE_PATH, payload, mode=0o640, owner="root", group=AUTHOS_USER
    )


def ensure_apply_request_file(paths: dict) -> None:
    if not paths["request_path"].exists():
        write_json(
            paths["request_path"],
            {"requested_at": None},
            mode=0o640,
            owner=AUTHOS_USER,
            group=AUTHOS_USER,
        )


def relocate_managed_paths(current_paths: dict, desired_paths: dict) -> None:
    ensure_dir(desired_paths["data_dir"], mode=0o700)

    for key in ("config_path", "state_path", "status_path"):
        move_path(current_paths[key], desired_paths[key])

    if current_paths["sqlite_dir"] != desired_paths["sqlite_dir"]:
        move_path(current_paths["sqlite_dir"], desired_paths["sqlite_dir"])

    cleanup_empty_dir(current_paths["data_dir"])


def move_path(source: Path, destination: Path) -> None:
    if source == destination or not source.exists():
        return

    ensure_dir(destination.parent, mode=0o755)

    if source.is_dir():
        if not destination.exists():
            shutil.move(str(source), str(destination))
            return

        ensure_dir(destination, mode=0o700)
        for entry in source.iterdir():
            move_path(entry, destination / entry.name)
        cleanup_empty_dir(source)
        return

    if destination.exists():
        if destination.is_dir():
            raise RuntimeError(f"Cannot replace directory with file: {destination}")
        destination.unlink()
    shutil.move(str(source), str(destination))


def cleanup_empty_dir(path: Path) -> None:
    if not path.exists() or not path.is_dir():
        return

    try:
        next(path.iterdir())
        return
    except StopIteration:
        path.rmdir()
    except OSError:
        return


def bootstrap_login_url(config: dict, state: dict) -> str:
    bootstrap = state.get("bootstrap_login") or {}
    token = bootstrap.get("token")
    if not token or bootstrap.get("used_at"):
        return ""
    return f"{config['deployment']['platformBaseUrl']}/bootstrap-login#token={quote(token)}"


def load_json(path: Path, default=None):
    if not path.exists():
        if default is not None:
            return default
        raise RuntimeError(f"Missing required file: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _owner_ids(path: Path, owner: str | None, group: str | None) -> tuple[int, int]:
    existing = path.stat() if path.exists() else None
    uid = pwd.getpwnam(owner).pw_uid if owner else (existing.st_uid if existing else os.geteuid())
    gid = grp.getgrnam(group).gr_gid if group else (existing.st_gid if existing else os.getegid())
    return uid, gid


def _atomic_replace_file(path: Path, mode: int, writer, owner: str | None = None, group: str | None = None) -> None:
    parent = path.parent
    parent_existed = parent.exists()
    parent.mkdir(parents=True, exist_ok=True)
    if not parent_existed:
        os.chmod(parent, 0o755)

    uid, gid = _owner_ids(path, owner, group)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=parent)
    temporary = Path(temporary_name)
    directory_fd = None
    try:
        with os.fdopen(fd, "wb") as handle:
            writer(handle)
            handle.flush()
            os.fchown(handle.fileno(), uid, gid)
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())

        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        os.fsync(directory_fd)
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_write_bytes(
    path: Path,
    payload: bytes,
    mode: int,
    owner: str | None = None,
    group: str | None = None,
) -> None:
    _atomic_replace_file(path, mode, lambda handle: handle.write(payload), owner, group)


def atomic_write_text(
    path: Path,
    payload: str,
    mode: int,
    owner: str | None = None,
    group: str | None = None,
) -> None:
    atomic_write_bytes(path, payload.encode("utf-8"), mode, owner, group)


def atomic_copy_file(
    source: Path,
    target: Path,
    mode: int,
    owner: str | None = None,
    group: str | None = None,
) -> None:
    def copy(handle) -> None:
        with source.open("rb") as source_handle:
            shutil.copyfileobj(source_handle, handle, length=1024 * 1024)

    _atomic_replace_file(target, mode, copy, owner, group)


def write_json(
    path: Path,
    value,
    mode: int,
    owner: str | None = None,
    group: str | None = None,
) -> None:
    atomic_write_bytes(
        path,
        (json.dumps(value, indent=2) + "\n").encode("utf-8"),
        mode,
        owner,
        group,
    )


def persist_state(paths: dict, state: dict) -> None:
    write_json(
        paths["state_path"],
        state,
        mode=0o640,
        owner=AUTHOS_USER,
        group=AUTHOS_USER,
    )


def write_env(
    path: Path,
    values: dict,
    mode: int,
    owner: str | None = None,
    group: str | None = None,
) -> None:
    lines = ["# Generated by AuthOS standalone apply. Edit config.json and rerun authos-apply instead."]
    for key in sorted(values.keys()):
        value = str(values[key])
        lines.append(f"{key}={quote_env(value)}")
    atomic_write_bytes(path, ("\n".join(lines) + "\n").encode("utf-8"), mode, owner, group)


def quote_env(value: str) -> str:
    if value == "":
        return ""
    if re.fullmatch(r"[A-Za-z0-9_./:@%+=,-]+", value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def detect_primary_ip() -> str:
    try:
        output = subprocess.check_output(["hostname", "-I"], text=True).strip().split()
        for candidate in output:
            if candidate and not candidate.startswith("127.") and ":" not in candidate:
                return candidate
    except Exception:
        pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip_address = sock.getsockname()[0]
        sock.close()
        if ip_address:
            return ip_address
    except Exception:
        pass

    return "127.0.0.1"


def wait_for_http_readiness(base_url: str) -> None:
    deadline = datetime.now(timezone.utc) + timedelta(seconds=90)
    last_error = "service did not respond"
    ready_url = f"{base_url.rstrip('/')}/health/ready"

    while datetime.now(timezone.utc) < deadline:
        try:
            payload = request_json(ready_url, method="GET")
            if payload.get("status") == "ready":
                return
            last_error = json.dumps(payload)
        except Exception as exc:
            last_error = str(exc)
        time_sleep(2)

    raise RuntimeError(f"Timed out waiting for {ready_url}. Last error: {last_error}")


class StandaloneHttpError(RuntimeError):
    def __init__(self, status: int, response_text: str):
        super().__init__(f"HTTP {status}: {response_text}")
        self.status = status
        self.response_text = response_text


def request_json(url: str, method: str = "GET", headers: dict | None = None, body=None):
    payload = None
    request_headers = dict(headers or {})
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        request_headers.setdefault("content-type", "application/json")
    request_headers.setdefault("accept", "application/json")
    request = urllib.request.Request(
        url,
        data=payload,
        method=method,
        headers=request_headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read().decode("utf-8")
            if not raw:
                return {}
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise StandaloneHttpError(exc.code, raw) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Request failed for {url}: {exc}") from exc


def wait_for_systemd(service_name: str) -> None:
    deadline = datetime.now(timezone.utc) + timedelta(seconds=90)
    while datetime.now(timezone.utc) < deadline:
        result = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip() == "active":
            return
        time_sleep(2)
    raise RuntimeError(f"Timed out waiting for {service_name} to become active")


def run(cmd: list[str], check: bool = True) -> None:
    result = subprocess.run(cmd, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(cmd)}")


def ensure_system_user() -> None:
    if subprocess.run(["id", "-u", AUTHOS_USER], capture_output=True).returncode == 0:
        return
    run(["useradd", "--system", "--create-home", "--home-dir", "/var/lib/authos", "--shell", "/usr/sbin/nologin", AUTHOS_USER])


def stop_existing_service() -> None:
    if shutil.which("systemctl") is None:
        return
    result = subprocess.run(
        ["systemctl", "list-unit-files", "authos.service", "--no-legend"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0 and "authos.service" in result.stdout:
        run(["systemctl", "stop", "authos.service"], check=False)


def require_root() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("This command must run as root")


def ensure_dir(path: Path, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)


def chown_path(path: Path, user: str, group: str) -> None:
    if not path.exists():
        return
    shutil.chown(path, user=user, group=group)


def add_if(target: dict, key: str, value) -> None:
    if value is None:
        return
    text = str(value).strip()
    if text:
        target[key] = text


def write_status(path: Path, payload: dict) -> None:
    try:
        write_json(
            path,
            payload,
            mode=0o640,
            owner=AUTHOS_USER,
            group=AUTHOS_USER,
        )
    except Exception:
        pass


def write_failure_status(message: str) -> None:
    paths = managed_paths()
    try:
        write_status(paths["status_path"], {
            "status": "error",
            "message": message,
            "updated_at": now_rfc3339(),
        })
    except Exception:
        pass


def print_failure_recovery_hint() -> None:
    try:
        paths = managed_paths()
        print("", file=sys.stderr)
        print("AuthOS saved its managed state before the failure.", file=sys.stderr)
        print(f"Config: {paths['config_path']}", file=sys.stderr)
        print(f"State: {paths['state_path']}", file=sys.stderr)
        print(f"Status: {paths['status_path']}", file=sys.stderr)
        print("Retry after fixing the issue with: sudo authos-apply apply --bundle-dir /opt/authos", file=sys.stderr)

        config = load_json(paths["config_path"], {})
        state = load_json(paths["state_path"], {})
        login_url = bootstrap_login_url(config, state) if config and state else ""
        if login_url:
            print(f"Bootstrap login link after the service is healthy: {login_url}", file=sys.stderr)
        print("", file=sys.stderr)
    except Exception:
        pass


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat()


def remove_legacy_sudoers() -> None:
    legacy_path = Path("/etc/sudoers.d/authos-apply")
    if legacy_path.exists():
        legacy_path.unlink()


def time_sleep(seconds: int) -> None:
    import time

    time.sleep(seconds)


if __name__ == "__main__":
    raise SystemExit(main())
