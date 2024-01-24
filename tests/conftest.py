from __future__ import annotations

import json
from contextlib import contextmanager
from multiprocessing import Process
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator

import pytest

from .utils import IP, PASSWORD, USERNAME


@contextmanager
def config_for_testing(custom_config: dict) -> Iterator[Path]:
    with TemporaryDirectory() as tmp_dir:
        config = Path(tmp_dir) / "config.json"
        logs_output_dir = Path(tmp_dir) / "logs"
        logs_output_dir.mkdir()
        testing_config = {
            "logs": "file,terminal,json",
            "logs_location": str(logs_output_dir.absolute()),
            **custom_config,
        }
        config.write_text(json.dumps(testing_config))
        yield config


@pytest.fixture()
def server_logs(request):
    custom_config = request.param.get("custom_config", {})
    with config_for_testing(custom_config) as config_file:
        _server = request.param["server"](
            ip=IP,
            port=request.param["port"],
            username=USERNAME,
            password=PASSWORD,
            options="",
            config=str(config_file.absolute()),
        )
        server_process = Process(target=_server.run_server)
        server_process.start()
        yield config_file.parent / "logs"
        server_process.terminate()
        server_process.join()
