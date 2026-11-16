"""The dependency rule of ``docs/DESIGN.md`` section 3, checked by walking the import graph.

    policy, scan, audit, auth and core.models do not import guard.
    Only core.service and lockdown drive enforcement, and only through the Enforcer interface.

Every module under ``src/portlock`` is parsed with ``ast`` (imports inside functions and
under ``TYPE_CHECKING`` count: a lazy import is still a dependency). The table below is
``docs/ARCHITECTURE.md`` section 1.2 as it was built, and the differences from that table
are stated next to the entries they concern.
"""

from __future__ import annotations

import ast
import sys
from collections import defaultdict
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"
ROOT = "portlock"


def module_name(path: Path) -> str:
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


MODULES: dict[str, Path] = {module_name(path): path for path in sorted((SRC / ROOT).rglob("*.py"))}


def imports_of(name: str) -> tuple[set[str], set[str]]:
    """``(internal, external)`` modules a module imports, wherever the import statement is."""
    tree = ast.parse(MODULES[name].read_text(encoding="utf-8"))
    package = name if MODULES[name].name == "__init__.py" else name.rpartition(".")[0]
    internal: set[str] = set()
    external: set[str] = set()

    def add(target: str) -> None:
        if target == ROOT or target.startswith(ROOT + "."):
            internal.add(target)
        else:
            external.add(target.split(".")[0])

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: len(base) - (node.level - 1)]
                module = ".".join(base + ([node.module] if node.module else []))
            else:
                module = node.module or ""
            add(module)
            for alias in node.names:
                add(f"{module}.{alias.name}")
    # ``from portlock.guard import factory`` names a module; ``from portlock.core.config
    # import Config`` does not. Only names that are modules of the package are edges.
    return {target for target in internal if target in MODULES}, external


GRAPH: dict[str, set[str]] = {}
EXTERNAL: dict[str, set[str]] = {}
for _name in MODULES:
    GRAPH[_name], EXTERNAL[_name] = imports_of(_name)


def package_of(name: str) -> str:
    parts = name.split(".")
    return ".".join(parts[:2]) if len(parts) > 1 else name


def reachable(start: str) -> set[str]:
    seen: set[str] = set()
    stack = [start]
    while stack:
        for target in GRAPH[stack.pop()]:
            if target not in seen:
                seen.add(target)
                stack.append(target)
    return seen


def modules_in(*prefixes: str) -> list[str]:
    return [
        name for name in MODULES if any(name == p or name.startswith(p + ".") for p in prefixes)
    ]


def is_guard(name: str) -> bool:
    return name == f"{ROOT}.guard" or name.startswith(f"{ROOT}.guard.")


# --- the rule of DESIGN section 3 ---------------------------------------------------------

PURE = modules_in(
    f"{ROOT}.policy", f"{ROOT}.scan", f"{ROOT}.audit", f"{ROOT}.auth", f"{ROOT}.core.models"
)


def test_the_walk_actually_sees_the_code() -> None:
    assert (
        len(MODULES) > 60 and f"{ROOT}.core.service" in MODULES and f"{ROOT}.console.api" in MODULES
    )
    assert "portlock.guard.base" in GRAPH["portlock.core.service"]
    assert "portlock.core.config" in GRAPH["portlock.console.api"]
    assert len(PURE) > 20


@pytest.mark.parametrize("module", PURE)
def test_policy_scan_audit_auth_and_core_models_do_not_import_guard(module: str) -> None:
    offending = sorted(target for target in GRAPH[module] if is_guard(target))
    assert offending == [], f"{module} imports {offending}"


@pytest.mark.parametrize("module", PURE)
def test_nor_does_anything_they_import_lead_back_to_the_enforcement_code(module: str) -> None:
    # Transitively: the pure packages must not reach the concrete backends or enforcers,
    # or the safety layer and the lockdown manager that drive them.
    reached = reachable(module)
    forbidden = [
        target
        for target in reached
        if target.startswith((f"{ROOT}.guard.linux", f"{ROOT}.guard.windows"))
        or target
        in {
            f"{ROOT}.guard.factory",
            f"{ROOT}.guard.safety",
            f"{ROOT}.lockdown.manager",
            f"{ROOT}.core.service",
            f"{ROOT}.service.daemon",
        }
    ]
    assert forbidden == [], f"{module} reaches {sorted(forbidden)}"


def test_the_pure_packages_may_not_import_the_console_or_the_service_either() -> None:
    for module in PURE:
        for target in GRAPH[module]:
            assert not target.startswith(
                (f"{ROOT}.console", f"{ROOT}.service", f"{ROOT}.lockdown")
            ), (
                module,
                target,
            )


# --- who may touch the guard at all -------------------------------------------------------

# module -> the guard modules it may import. Everything else imports no guard module.
GUARD_USERS: dict[str, set[str]] = {
    # Types only: the journal entry and the enforcement vocabulary.
    f"{ROOT}.core.store": {f"{ROOT}.guard.base"},
    f"{ROOT}.lockdown.manager": {f"{ROOT}.guard.base"},
    # The pipeline: the interfaces and the one safety choke point, never a concrete enforcer.
    f"{ROOT}.core.service": {f"{ROOT}.guard.base", f"{ROOT}.guard.safety"},
    # The composition root: platform factories, the fakes of simulation, the seams.
    f"{ROOT}.service.daemon": {
        f"{ROOT}.guard",
        f"{ROOT}.guard.base",
        f"{ROOT}.guard.factory",
        f"{ROOT}.guard.fake",
        f"{ROOT}.guard.safety",
        f"{ROOT}.guard.seams",
    },
    # ``portlock recover`` builds the platform enforcer behind the safety layer.
    f"{ROOT}.console.cli": {
        f"{ROOT}.guard",
        f"{ROOT}.guard.base",
        f"{ROOT}.guard.factory",
        f"{ROOT}.guard.safety",
    },
    # The simulator takes the fakes directly and never the factory: it cannot pick a real one.
    f"{ROOT}.console.simulate": {f"{ROOT}.guard.base", f"{ROOT}.guard.fake", f"{ROOT}.guard.seams"},
}


@pytest.mark.parametrize("module", [m for m in MODULES if not is_guard(m)])
def test_only_the_named_modules_import_the_guard_and_only_what_they_are_allowed(
    module: str,
) -> None:
    used = {target for target in GRAPH[module] if is_guard(target)}
    assert used <= GUARD_USERS.get(module, set()), (
        f"{module} imports {sorted(used - GUARD_USERS.get(module, set()))}"
    )


def test_the_simulator_never_imports_the_platform_factory_or_a_concrete_enforcer() -> None:
    reached = reachable(f"{ROOT}.console.simulate")
    # It does reach the daemon (to build a runtime), which knows the factory, but its own
    # imports name only the fakes: the run-time proof is in test_console_simulate.
    own = GRAPH[f"{ROOT}.console.simulate"]
    assert f"{ROOT}.guard.factory" not in own
    assert not any(t.startswith((f"{ROOT}.guard.linux", f"{ROOT}.guard.windows")) for t in own)
    assert f"{ROOT}.service.daemon" in reached


def test_nothing_outside_the_guard_package_imports_a_platform_package() -> None:
    # The Linux and Windows code is reached only through guard.factory (lazily) and the
    # guard package's own seams; the pipeline, the console and the daemon never name it.
    for module in MODULES:
        if is_guard(module):
            continue
        for target in GRAPH[module]:
            assert not target.startswith((f"{ROOT}.guard.linux", f"{ROOT}.guard.windows")), (
                module,
                target,
            )
    assert f"{ROOT}.guard.linux.enforce" in GRAPH[f"{ROOT}.guard.factory"]


# --- the rest of the table in ARCHITECTURE section 1.2 ------------------------------------

# module -> the first-party modules it may import (a prefix allows its submodules).
# Deviations from the table in ARCHITECTURE 1.2, each there because the code needs it:
#   console.api    imports lockdown.manager for the ``Credential`` value type and the two
#                  error classes it must map to HTTP statuses; it drives nothing there.
#   console.simulate imports scan.report (to build a synthetic report), console.api (to
#                  serve) and the guard fakes and seams, never the platform factory.
ALLOWED: dict[str, tuple[str, ...]] = {
    f"{ROOT}.service.install": (f"{ROOT}.core.config", f"{ROOT}.core.errors"),
    f"{ROOT}.console.api": (
        f"{ROOT}.core.service",
        f"{ROOT}.core.config",
        f"{ROOT}.core.clock",
        f"{ROOT}.core.errors",
        f"{ROOT}.core.models",
        f"{ROOT}.core.events",
        f"{ROOT}.auth",
        f"{ROOT}.audit",
        f"{ROOT}.lockdown.manager",
        ROOT,
    ),
    f"{ROOT}.console.simulate": (
        f"{ROOT}.service.daemon",
        f"{ROOT}.core",
        f"{ROOT}.guard.fake",
        f"{ROOT}.guard.seams",
        f"{ROOT}.guard.base",
        f"{ROOT}.console",
        f"{ROOT}.audit.log",
        f"{ROOT}.lockdown.manager",
        f"{ROOT}.scan.report",
        ROOT,
    ),
}


@pytest.mark.parametrize("module", sorted(ALLOWED))
def test_a_module_imports_only_what_the_architecture_table_allows(module: str) -> None:
    allowed = ALLOWED[module]
    for target in GRAPH[module]:
        if target == module or target.startswith(module + "."):
            continue
        assert target == ROOT or any(target == a or target.startswith(a + ".") for a in allowed), (
            f"{module} imports {target}"
        )


def test_console_api_does_not_import_the_daemon_the_store_or_the_guard() -> None:
    for target in GRAPH[f"{ROOT}.console.api"]:
        assert not is_guard(target)
        assert target not in {f"{ROOT}.core.store", f"{ROOT}.service.daemon", f"{ROOT}.console.cli"}
        assert not target.startswith(f"{ROOT}.guard")


def test_the_daemon_is_not_imported_by_the_api_so_the_two_can_be_wired_together() -> None:
    assert f"{ROOT}.console.api" not in GRAPH[f"{ROOT}.service.daemon"]
    assert f"{ROOT}.service.daemon" not in reachable(f"{ROOT}.console.api")


def test_there_are_no_import_cycles_between_packages_the_rule_forbids() -> None:
    # core must not import the console, the service process or the lockdown manager's callers.
    for module in modules_in(f"{ROOT}.core"):
        for target in GRAPH[module]:
            assert not target.startswith((f"{ROOT}.console", f"{ROOT}.service")), (module, target)
    for module in modules_in(f"{ROOT}.guard"):
        for target in GRAPH[module]:
            assert not target.startswith(
                (f"{ROOT}.console", f"{ROOT}.service", f"{ROOT}.lockdown")
            ), (
                module,
                target,
            )


# --- third parties ------------------------------------------------------------------------


def test_the_runtime_uses_the_standard_library_and_optionally_cryptography_only() -> None:
    stdlib = set(sys.stdlib_module_names)
    for module, names in EXTERNAL.items():
        for name in names:
            assert name in stdlib or name == "cryptography", f"{module} imports {name}"
    users = [module for module, names in EXTERNAL.items() if "cryptography" in names]
    assert users == [f"{ROOT}.audit.signing"]


def test_cryptography_is_imported_lazily_only() -> None:
    tree = ast.parse(MODULES[f"{ROOT}.audit.signing"].read_text(encoding="utf-8"))
    for node in tree.body:  # top-level statements only
        if isinstance(node, ast.Import):
            assert all(not alias.name.startswith("cryptography") for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("cryptography")


def test_the_graph_has_no_unresolvable_first_party_import() -> None:
    unknown: dict[str, set[str]] = defaultdict(set)
    for module, path in MODULES.items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.level == 0
                and node.module
                and node.module.startswith(ROOT + ".")
                and node.module not in MODULES
            ):
                unknown[module].add(node.module)
    assert dict(unknown) == {}
