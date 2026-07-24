"""Standard ASGI entry point for hosted SCT comparison deployments."""

from .web import create_app_from_env


app = create_app_from_env()
