import importlib

import pytest

import secaudit
from secaudit.cli import main

SUBPACKAGES = ["core", "agents", "api", "mcp_server"]


def test_package_has_version():
    assert secaudit.__version__


@pytest.mark.parametrize("name", SUBPACKAGES)
def test_subpackages_import(name):
    assert importlib.import_module(f"secaudit.{name}")


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"secaudit {secaudit.__version__}"
