from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


@pytest.fixture
def config_for_testing() -> Path:
    with TemporaryDirectory() as tmp_dir:
        config = Path(tmp_dir) / "config.json"
        logs_output_dir = Path(tmp_dir) / "logs"
        logs_output_dir.mkdir()
        testing_config = {
            "logs": "file,terminal,json",
            "logs_location": str(logs_output_dir.absolute()),
        }
        config.write_text(json.dumps(testing_config))
        yield config
