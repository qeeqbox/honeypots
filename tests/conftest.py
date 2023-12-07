from __future__ import annotations

import json
from multiprocessing import Process
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from .utils import IP, PASSWORD, USERNAME


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


def _update_config(custom_config: dict, config_path: Path):
    config = json.loads(config_path.read_text())
    config.update(custom_config)
    config_path.write_text(json.dumps(config))


@pytest.fixture
def server_logs(request, config_for_testing: Path):
    custom_config = request.param.get("custom_config", {})
    if custom_config:
        _update_config(custom_config, config_for_testing)
    _server = request.param["server"](
        ip=IP,
        port=request.param["port"],
        username=USERNAME,
        password=PASSWORD,
        options="",
        config=str(config_for_testing.absolute()),
    )
    server_process = Process(target=_server.run_server)
    server_process.start()
    yield config_for_testing.parent / "logs"
    server_process.terminate()
    server_process.join()
