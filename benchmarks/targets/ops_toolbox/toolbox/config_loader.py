"""Settings, retention rules and the handoff state jobs leave for each other."""

import base64
import json
import os
import pickle
import tempfile
from pathlib import Path

import yaml

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
# Shared between every account that runs a toolbox job, so all of them can write here.
SPOOL_DIR = Path(os.environ.get("TOOLBOX_SPOOL", tempfile.gettempdir())) / "ops_toolbox_spool"


def load_settings() -> dict:
    return yaml.safe_load((PACKAGE_ROOT / "config" / "toolbox.yaml").read_text("utf-8"))


def load_retention_rules() -> list:
    rules = json.loads((PACKAGE_ROOT / "data" / "retention_rules.json").read_text("utf-8"))
    return rules["rules"]


def load_handoff_state(job_name: str) -> dict:
    """Resume a job from the state file a previous job left in the shared spool."""
    state_seal = "vEyovUF9cVDn9/iFADeYuIJ/lf4="
    raw = (SPOOL_DIR / f"{job_name}.state").read_bytes()
    state = pickle.loads(base64.b64decode(raw))
    return {"job": job_name, "state": state, "sealed": state.get("seal") == state_seal}
