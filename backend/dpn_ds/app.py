"""HTTP API: bearer-token gated, read-only, and localhost by deployment default."""

from __future__ import annotations

import logging
import sys
import time

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from dpn_ds.advanced_health import AdvancedHealth
from dpn_ds.audit import LOGGER, emit_audit_event
from dpn_ds.config import Settings
from dpn_ds.diagnostics import DomainDiagnostics
from dpn_ds.directory import DemoDirectory, Directory, DirectoryUnavailable, SambaDirectory
from dpn_ds.identity import OperatorAuthenticator


def create_app(
    settings: Settings | None = None,
    directory: Directory | None = None,
    public_key: str | None = None,
) -> FastAPI:
    cfg = settings if settings is not None else Settings.from_env()
    source: Directory = directory or (DemoDirectory() if cfg.mode == "demo" else SambaDirectory())
    authenticator = OperatorAuthenticator(cfg, public_key=public_key)
    LOGGER.setLevel(logging.INFO)
    if not LOGGER.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        LOGGER.addHandler(handler)

    application = FastAPI(
        title="DPN Directory Services API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    if cfg.cors_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=list(cfg.cors_origins),
            allow_credentials=False,
            allow_methods=["GET"],
            allow_headers=["Authorization"],
        )

    @application.middleware("http")
    async def security_event_stream(request: Request, call_next):
        if not request.url.path.startswith("/api/v1/"):
            return await call_next(request)
        started = time.monotonic()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            duration = int((time.monotonic() - started) * 1000)
            emit_audit_event(request, status, duration)

    @application.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    router = APIRouter(prefix="/api/v1", dependencies=[Depends(authenticator.verify)])

    def read_items(method: str) -> list[dict[str, str]]:
        try:
            return getattr(source, method)()
        except DirectoryUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @router.get("/session")
    def session(request: Request) -> dict[str, str]:
        actor = request.state.operator
        return {"role": actor.role, "auth_mode": actor.method}

    @router.get("/users")
    def users() -> dict:
        return {"items": read_items("users"), "mode": cfg.mode}

    @router.get("/groups")
    def groups() -> dict:
        return {"items": read_items("groups"), "mode": cfg.mode}

    @router.get("/devices")
    def devices() -> dict:
        return {"items": read_items("devices"), "mode": cfg.mode}

    @router.get("/diagnostics")
    def diagnostics() -> dict:
        """Only server-defined diagnostic targets; no user-supplied scan parameters."""
        return DomainDiagnostics(cfg.realm, cfg.controller, cfg.mode).snapshot()

    @router.get("/advanced-health")
    def advanced_health() -> dict:
        """Opt-in account authentication and local replication diagnostics."""
        return AdvancedHealth(cfg).snapshot()

    @router.get("/overview")
    def overview() -> dict:
        users_list = read_items("users")
        groups_list = read_items("groups")
        devices_list = read_items("devices")
        try:
            status = source.controller_status()
        except DirectoryUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {
            "name": "DPN Directory Services",
            "version": "0.1.0",
            "realm": cfg.realm,
            "controller": cfg.controller,
            "mode": cfg.mode,
            "controller_status": status,
            "counts": {
                "users": len(users_list),
                "groups": len(groups_list),
                "devices": len(devices_list),
            },
        }

    application.include_router(router)
    return application


app = create_app()
