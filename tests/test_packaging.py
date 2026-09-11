#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""Tests for the repository layout, the manifest and the .mkp builder."""

from __future__ import annotations

import ast
import json
import sys
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_mkp  # noqa: E402

PLUGIN_ROOT = REPO_ROOT / "local/lib/python3/cmk_addons/plugins/paloalto_api"


@pytest.fixture(scope="module")
def manifest() -> dict:
    return build_mkp.load_manifest(REPO_ROOT / "package.manifest")


def test_manifest_matches_the_local_tree(manifest):
    problems = build_mkp.check_manifest(manifest, build_mkp.scan_parts(REPO_ROOT))
    assert problems == [], "run 'python3 scripts/build_mkp.py --update-manifest'"


def test_versions_agree(manifest):
    assert build_mkp.check_versions(REPO_ROOT, manifest) == []


def test_manifest_has_the_fields_checkmk_requires(manifest):
    for key in (
        "name",
        "title",
        "version",
        "version.min_required",
        "version.packaged",
        "version.usable_until",
        "author",
        "description",
        "download_url",
        "files",
    ):
        assert key in manifest, key
    assert manifest["name"] == "paloalto_api"


def test_every_plugin_directory_is_present():
    for subdir in (
        "agent_based",
        "checkman",
        "graphing",
        "libexec",
        "rulesets",
        "server_side_calls",
    ):
        assert (PLUGIN_ROOT / subdir).is_dir(), subdir


def test_the_special_agent_is_executable():
    agent = PLUGIN_ROOT / "libexec/agent_paloalto_api"
    assert agent.stat().st_mode & 0o111, "agent_paloalto_api must be executable"


@pytest.mark.parametrize(
    "path",
    sorted(
        p.relative_to(REPO_ROOT) for p in PLUGIN_ROOT.rglob("*.py") if "__pycache__" not in p.parts
    ),
    ids=str,
)
def test_plugin_files_are_valid_python(path):
    """Syntax check without importing - the cmk modules only exist in a site."""
    ast.parse((REPO_ROOT / path).read_text(encoding="utf-8"), filename=str(path))


def test_every_check_plugin_has_a_checkman_page():
    """Each 'CheckPlugin(name=...)' needs a man page of the same name."""
    documented = {p.name for p in (PLUGIN_ROOT / "checkman").iterdir() if p.is_file()}
    declared = set()
    for source in (PLUGIN_ROOT / "agent_based").glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "CheckPlugin"
            ):
                for keyword in node.keywords:
                    if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                        declared.add(keyword.value.value)
    assert declared, "no CheckPlugin found"
    assert declared - documented == set(), f"missing checkman pages: {declared - documented}"


def test_build_produces_an_installable_mkp(tmp_path, manifest):
    target = build_mkp.build_mkp(REPO_ROOT, manifest, tmp_path)
    assert target.is_file()

    with tarfile.open(target, "r:gz") as tar:
        names = tar.getnames()
        assert "info" in names
        assert "info.json" in names
        assert "cmk_addons_plugins.tar" in names

        packaged = json.loads(tar.extractfile("info.json").read())
        assert packaged == manifest

        part = tar.extractfile("cmk_addons_plugins.tar")
        with tarfile.open(fileobj=part, mode="r:") as inner:
            members = {m.name: m for m in inner.getmembers()}

    assert set(members) == set(manifest["files"]["cmk_addons_plugins"])
    # the agent keeps its executable bit, everything else does not get one
    assert members["paloalto_api/libexec/agent_paloalto_api"].mode == 0o755
    assert members["paloalto_api/agent_based/paloalto_api_system.py"].mode == 0o644
    # tar entries are owned by root so unpacking in a site is predictable
    assert all(m.uid == 0 and m.gid == 0 for m in members.values())


def test_the_info_member_is_readable_by_checkmk(tmp_path, manifest):
    """Checkmk reads the 'info' member as a Python literal."""
    target = build_mkp.build_mkp(REPO_ROOT, manifest, tmp_path)
    with tarfile.open(target, "r:gz") as tar:
        info = ast.literal_eval(tar.extractfile("info").read().decode("utf-8"))
    assert info == manifest


def test_choice_element_names_are_valid_python_identifiers():
    """Checkmk rejects a rule spec whose choice names are not identifiers.

    A hyphen here makes the whole rule spec fail to load, which also breaks
    the CheckPlugin that references it - and only shows up inside a site.
    """
    import keyword

    offenders = []
    for source in (PLUGIN_ROOT / "rulesets").glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("SingleChoiceElement", "MultipleChoiceElement")
            ):
                for keyword_arg in node.keywords:
                    if keyword_arg.arg != "name" or not isinstance(keyword_arg.value, ast.Constant):
                        continue
                    name = keyword_arg.value.value
                    if not name.isidentifier() or keyword.iskeyword(name):
                        offenders.append(f"{source.name}: {name}")
    assert offenders == [], f"not valid Python identifiers: {offenders}"
