from __future__ import annotations

from contextlib import contextmanager
from multiprocessing import Process
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator

import pytest

from .utils import IP, PASSWORD, USERNAME


@contextmanager
def get_log_dir() -> Iterator[Path]:
    with TemporaryDirectory() as tmp_dir:
        logs_output_dir = Path(tmp_dir) / "logs"
        logs_output_dir.mkdir()
        yield logs_output_dir


@pytest.fixture()
def server_logs(request):
    custom_config = request.param.get("custom_config", {})
    with get_log_dir() as log_dir:
        custom_config.update(
            {
                "logs": "file,terminal,json",
                "logs_location": str(log_dir.absolute()),
            }
        )
        _server = request.param["server"](
            ip=IP,
            port=request.param["port"],
            username=USERNAME,
            password=PASSWORD,
            options="",
            config=custom_config,
        )
        server_process = Process(target=_server.run_server)
        server_process.start()
        yield log_dir
        server_process.terminate()
        server_process.join()
