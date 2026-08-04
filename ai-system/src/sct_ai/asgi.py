"""Standard ASGI entry point for hosted SCT comparison deployments."""

from .environment import load_repository_environment
from .web import create_app_from_env


load_repository_environment()
app = create_app_from_env()
