"""Project hygiene: packaging metadata, PEP 561, and the light-import promise.

These tests guard things that are easy to break silently -- a marker file that
never ships, a re-export missing from ``__all__``, an optional dependency that
suddenly becomes a hard one, documentation that points at a file nobody wrote.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import arena_api

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    tomllib = pytest.importorskip("tomli")  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "arena_api"
HEAVY = (
    "playwright",
    "rookiepy",
    "arena_api._vendor.recaptcha_toolkit",
    "curl_cffi",
    "torch",
    "selenium",
    "playwright_recaptcha",
)


@pytest.fixture(scope="module")
def pyproject() -> dict:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def test_package_ships_a_pep561_marker(pyproject: dict) -> None:
    """Without ``py.typed`` type checkers ignore every annotation we wrote."""
    assert (PACKAGE / "py.typed").is_file()
    assert "py.typed" in pyproject["tool"]["setuptools"]["package-data"]["arena_api"]


def test_every_exported_name_exists() -> None:
    assert [name for name in arena_api.__all__ if not hasattr(arena_api, name)] == []


def test_every_reexport_is_listed_in_all() -> None:
    """A name imported into ``__init__`` but absent from ``__all__`` is invisible
    to ``from arena_api import *`` and reads as an unused import to linters."""
    tree = ast.parse((PACKAGE / "__init__.py").read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 1:
            imported.update(alias.asname or alias.name for alias in node.names)
    assert sorted(imported - set(arena_api.__all__)) == []


def test_the_auth_subpackage_exports_match_its_list() -> None:
    """Same hygiene as the top level, one level down.

    ``arena_api/auth/__init__.py`` re-exports a hundred names by hand; without
    this, a missed entry silently disappears from ``from arena_api.auth import *``
    and a duplicated one makes the package look like it lost track of itself.
    """
    from arena_api import auth

    tree = ast.parse((PACKAGE / "auth" / "__init__.py").read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 1:
            imported.update(alias.asname or alias.name for alias in node.names)

    assert sorted(imported - set(auth.__all__)) == []
    duplicates = sorted(
        name for name in set(auth.__all__) if auth.__all__.count(name) > 1
    )
    assert duplicates == []
    assert [name for name in auth.__all__ if not hasattr(auth, name)] == []


def test_importing_the_package_pulls_no_heavy_dependency() -> None:
    code = (
        "import sys, arena_api\n"
        f"heavy = [name for name in {HEAVY!r} if name in sys.modules]\n"
        "raise SystemExit(f'import arena_api pulled in: {heavy}' if heavy else 0)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=180
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


def test_console_script_points_at_a_callable(pyproject: dict) -> None:
    target = pyproject["project"]["scripts"]["arena-api"]
    assert target == "arena_api.auto:main"
    module_name, _, attribute = target.partition(":")
    module = __import__(module_name, fromlist=[attribute])
    assert callable(getattr(module, attribute))


def test_documented_extras_exist(pyproject: dict) -> None:
    extras = pyproject["project"]["optional-dependencies"]
    for name in ("test", "dev", "firefox", "e2e", "captcha", "auth-captcha", "auto", "vision", "impersonate"):
        assert name in extras, name
    # The zero-config extra must cover both halves of the promise.
    assert any("rookiepy" in item for item in extras["auto"])
    assert any("playwright-recaptcha" in item for item in extras["auto"])
    assert any("curl_cffi" in item for item in extras["auto"])
    # The zero-config path must be able to send the session's own fingerprint.
    assert any("httpx-curl-cffi" in item for item in extras["auto"])
    assert any("curl-cffi" in item for item in extras["impersonate"])
    assert any("httpx-curl-cffi" in item for item in extras["impersonate"])
    # The base install stays dependency-light.
    assert pyproject["project"]["dependencies"] == ["httpx[http2]>=0.27,<1"]


def test_python_floor_matches_the_ci_matrix(pyproject: dict) -> None:
    assert pyproject["project"]["requires-python"] == ">=3.10"
    assert pyproject["tool"]["mypy"]["python_version"] == "3.10"
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    assert '"3.10"' in workflow


def test_version_is_recorded_in_the_changelog(pyproject: dict) -> None:
    version = pyproject["project"]["version"]
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## {version}" in changelog


def test_readme_mentions_every_example() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    examples = sorted(path.name for path in (ROOT / "examples").glob("*.py"))
    assert examples, "the example scripts disappeared"
    assert [name for name in examples if name not in readme] == []


def test_readme_documents_the_bootstrap_commands() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for command in (
        "auto_client()",
        "python -m arena_api --explain",
        "python -m arena_api --status",
        "arena-api --status",
    ):
        assert command in readme, command


def test_tooling_configuration_is_present(pyproject: dict) -> None:
    assert pyproject["tool"]["pytest"]["ini_options"]["testpaths"] == ["tests"]
    assert pyproject["tool"]["mypy"]["files"] == ["arena_api"]
    assert pyproject["tool"]["mypy"]["check_untyped_defs"] is True
    assert "pyflakes" in " ".join(pyproject["project"]["optional-dependencies"]["dev"])


def test_build_artifacts_are_not_tracked() -> None:
    """``*.egg-info`` is generated; tracking it makes every metadata change noisy."""
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "*.egg-info/" in ignore
    listed = subprocess.run(
        ["git", "ls-files", "arena_api.egg-info"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert listed.returncode == 0
    assert listed.stdout.strip() == "", listed.stdout


def test_recaptcha_toolkit_is_vendored_inside_the_package() -> None:
    """The toolkit ships as ``arena_api._vendor.recaptcha_toolkit``.

    A top-level ``recaptcha_toolkit`` module would collide with a same-named
    project on PyPI -- whoever installs last wins. Vendoring removes that race,
    and the ``arena_api*`` include glob picks the subpackage up automatically.
    """
    vendor = PACKAGE / "_vendor" / "recaptcha_toolkit"
    assert (vendor / "__init__.py").is_file()
    assert (PACKAGE / "_vendor" / "__init__.py").is_file()
    assert not (ROOT / "recaptcha_toolkit").exists()

    includes = pyproject_includes()
    assert includes == ["arena_api*"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "arena_api._vendor.recaptcha_toolkit" in readme


def pyproject_includes() -> list[str]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        data = tomllib.load(handle)
    return data["tool"]["setuptools"]["packages"]["find"]["include"]


def test_license_is_declared_and_shipped(pyproject: dict) -> None:
    """A public package without a licence file is unusable by default: copyright
    law reserves all rights, so downstream cannot legally copy it."""
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.lstrip().startswith("Apache License")
    assert "Version 2.0" in text
    assert "END OF TERMS AND CONDITIONS" in text

    assert pyproject["project"]["license"] == "Apache-2.0"
    assert pyproject["project"]["license-files"] == ["LICENSE"]
    # PEP 639: the SPDX expression supersedes the "License ::" classifier, and
    # setuptools >= 77 refuses to build when both are present.
    classifiers = pyproject["project"].get("classifiers", [])
    assert not any(item.startswith("License ::") for item in classifiers)
    assert any("setuptools>=77" in req for req in pyproject["build-system"]["requires"])

    assert "Apache-2.0" in (ROOT / "README.md").read_text(encoding="utf-8")
