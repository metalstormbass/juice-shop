import re
import tomllib
from pathlib import PurePosixPath

from pydantic import Field, field_validator

from .models import Record


class Config(Record):
    repository: str = "local/repository"
    lockfile: str = "package-lock.json"
    model: str = "gpt-4.1-mini"
    agent_calls: int = Field(default=8, ge=0, le=60)
    remediation_attempts: int = Field(default=2, ge=1, le=4)
    input_cost_per_million: float = Field(default=0.4, ge=0)
    output_cost_per_million: float = Field(default=1.6, ge=0)
    # Enable tests only for a trusted checkout and a reviewed npm test script.
    run_npm_tests: bool = False
    # Packages whose reviewed install scripts run after `npm ci --ignore-scripts` (for native binaries).
    rebuild_packages: list[str] = []
    # npm argument lists run in order with the container network disabled.
    test_commands: list[list[str]] = [["test", "--ignore-scripts"]]

    # Maintainer-selected, existing tests of security behavior. Keys are npm package names.
    prepare_frontend: bool = False
    advisory_behavior_tests: dict[str, list[list[str]]] = {}

    @field_validator("advisory_behavior_tests")
    @classmethod
    def advisory_commands(cls, value):
        for advisory, commands in value.items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]+", advisory):
                raise ValueError("Expected an advisory identifier")
            cls.npm_commands(commands)
        return value

    security_behavior_tests: dict[str, list[list[str]]] = {}

    @field_validator("security_behavior_tests")
    @classmethod
    def behavior_commands(cls, value):
        cls.package_names(list(value))
        for commands in value.values():
            cls.npm_commands(commands)
        return value

    @field_validator("rebuild_packages")
    @classmethod
    def package_names(cls, value):
        if not all(re.fullmatch(r"(@[a-z0-9._-]+/)?[a-z0-9._-]+", name) for name in value):
            raise ValueError("Expected npm package names")
        return value

    @field_validator("test_commands")
    @classmethod
    def npm_commands(cls, value):
        if not value or not all(command and command[0] in ("test", "run", "exec") for command in value):
            raise ValueError("Expected npm test, run or exec argument lists")
        return value

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
