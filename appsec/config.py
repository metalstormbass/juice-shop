import re
import tomllib
from pathlib import PurePosixPath

from pydantic import Field, field_validator

from .models import Record


class Config(Record):
    repository: str = "local/repository"
    lockfile: str = "package-lock.json"
    model: str = "gpt-4.1-mini"
    agent_calls: int = Field(default=8, ge=0, le=30)
    remediation_attempts: int = Field(default=2, ge=1, le=4)
    input_cost_per_million: float = Field(default=0.4, ge=0)
    output_cost_per_million: float = Field(default=1.6, ge=0)
    # Enable tests only for a trusted checkout and a reviewed npm test script.
    run_npm_tests: bool = False

    @field_validator("lockfile")
    @classmethod
    def relative_lockfile(cls, value):
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or path.name != "package-lock.json" or str(path) != value:
            raise ValueError("Expected a repository-relative package-lock.json path")
        return value

    @field_validator("repository")
    @classmethod
    def github_slug(cls, value):
        if not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", value):
            raise ValueError("Expected an owner/repository slug")
        return value


def load(path):
    return Config.model_validate(tomllib.loads(path.read_text()))
