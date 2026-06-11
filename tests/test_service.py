import json
import logging

import pytest
from plumbum import ProcessExecutionError
from plumbum.cmd import docker

logger = logging.getLogger()


def _check_permissions(allowed_calls, forbidden_calls):
    for args in allowed_calls:
        docker(*args)
    for args in forbidden_calls:
        with pytest.raises(ProcessExecutionError):
            docker(*args)


def test_default_permissions(proxy_factory):
    with proxy_factory() as test_container:
        allowed_calls = (("version",),)
        forbidden_calls = (
            ("pull", "alpine"),
            ("--rm", "alpine", "--name", test_container),
            ("logs", test_container),
            ("wait", test_container),
            ("rm", "-f", test_container),
            ("restart", test_container),
            ("network", "ls"),
            ("config", "ls"),
            ("service", "ls"),
            ("stack", "ls"),
            ("secret", "ls"),
            ("plugin", "ls"),
            ("info",),
            ("system", "info"),
            ("build", "."),
            ("buildx build", "."),
            ("swarm", "init"),
        )
        _check_permissions(allowed_calls, forbidden_calls)


def test_container_permissions(proxy_factory):
    with proxy_factory(CONTAINERS=1) as test_container:
        allowed_calls = [
            ("logs", test_container),
            ("inspect", test_container),
        ]
        forbidden_calls = [
            ("wait", test_container),
            ("run", "--rm", "alpine"),
            ("rm", "-f", test_container),
            ("restart", test_container),
        ]
        _check_permissions(allowed_calls, forbidden_calls)


def test_container_inspect_env_stripped(proxy_factory):
    secret_env = "MY_SECRET_KEY=supersecret123"
    container_name = "test_env_stripping"
    docker(
        "run",
        "-d",
        "--name",
        container_name,
        "-e",
        secret_env,
        "alpine",
        "sleep",
        "100",
    )
    try:
        with proxy_factory(CONTAINERS=1):
            inspect_output = docker("inspect", container_name)
            inspect_data = json.loads(inspect_output)
            env = inspect_data[0]["Config"]["Env"]
            assert env == [], f"Expected empty Env, got: {env}"
            assert (
                secret_env not in inspect_output
            ), "Secret env value found in inspect output"
    finally:
        docker("rm", "-f", container_name)


def test_container_inspect_cmd_and_args_stripped(proxy_factory):
    secret_cmd = "SECRET_IN_CMD=supersecret456"
    container_name = "test_cmd_stripping"
    docker(
        "run",
        "-d",
        "--name",
        container_name,
        "alpine",
        "sh",
        "-c",
        f"echo {secret_cmd}; sleep 100",
    )
    try:
        with proxy_factory(CONTAINERS=1):
            inspect_output = docker("inspect", container_name)
            inspect_data = json.loads(inspect_output)
            cmd = inspect_data[0]["Config"]["Cmd"]
            args = inspect_data[0]["Args"]
            assert cmd == [], f"Expected empty Config.Cmd, got: {cmd}"
            assert args == [], f"Expected empty Args, got: {args}"
            assert (
                secret_cmd not in inspect_output
            ), "Secret command-line value found in inspect output"
    finally:
        docker("rm", "-f", container_name)


def test_post_permissions(proxy_factory):
    with proxy_factory(POST=1) as test_container:
        allowed_calls = []
        forbidden_calls = [
            ("rm", "-f", test_container),
            ("pull", "alpine"),
            ("run", "--rm", "alpine"),
            ("network", "create", "foobar"),
        ]
        _check_permissions(allowed_calls, forbidden_calls)


def test_network_post_permissions(proxy_factory):
    with proxy_factory(POST=1, NETWORKS=1):
        allowed_calls = [
            ("network", "ls"),
            ("network", "create", "foo"),
            ("network", "rm", "foo"),
        ]
        forbidden_calls = []
        _check_permissions(allowed_calls, forbidden_calls)


def test_exec_permissions(proxy_factory):
    with proxy_factory(CONTAINERS=1, EXEC=1, POST=1) as container_id:
        allowed_calls = [
            ("exec", container_id, "ls"),
        ]
        forbidden_calls = []
        _check_permissions(allowed_calls, forbidden_calls)
