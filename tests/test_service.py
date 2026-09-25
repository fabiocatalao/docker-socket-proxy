import json
import logging
import urllib.error
import urllib.request
import uuid

import pytest
from plumbum import ProcessExecutionError, local
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
        allowed_calls = (
            ("version",),
            # Bounded window, so the stream ends instead of following
            ("events", "--since", "1m", "--until", "1s"),
        )
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
            ("ps",),
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


# Brackets, quotes and backslashes inside the value exercise the JSON-aware
# scanner in filter_inspect.lua; the second variable checks that stripping
# doesn't stop at the first unbalanced bracket.
SECRET_ENV = ('TRICKY=]hunter2"[\\', "AFTER=hunter2")


@pytest.fixture(scope="module")
def secret_container():
    """Run a container with secrets in its env; yields `(id, name)`."""
    name = f"test_hide_env_{uuid.uuid4().hex[:8]}"
    env_args = [f"--env={item}" for item in SECRET_ENV]
    container_id = docker(
        "run", "--detach", f"--name={name}", *env_args, "alpine", "sleep", "300"
    ).strip()
    try:
        yield container_id, name
    finally:
        docker("rm", "-f", container_id)


def _proxy_get(path):
    """GET `path` straight through the proxy, bypassing the Docker CLI."""
    url = local.env["DOCKER_HOST"].replace("tcp://", "http://", 1) + path
    try:
        with urllib.request.urlopen(url) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def test_container_env_visible_by_default(proxy_factory, secret_container):
    container_id, _ = secret_container
    with proxy_factory(CONTAINERS=1):
        data = json.loads(docker("inspect", container_id))
        for item in SECRET_ENV:
            assert item in data[0]["Config"]["Env"]


def test_container_env_hidden(proxy_factory, secret_container):
    container_id, name = secret_container
    with proxy_factory(CONTAINERS=1, HIDE_CONTAINER_ENV=1):
        output = docker("inspect", name)
        assert "hunter2" not in output
        data = json.loads(output)
        assert data[0]["Id"] == container_id
        assert data[0]["Config"]["Env"] == []
        assert data[0]["Config"]["Image"] == "alpine"


def test_container_env_hidden_requires_containers(proxy_factory, secret_container):
    container_id, _ = secret_container
    with proxy_factory(HIDE_CONTAINER_ENV=1), pytest.raises(ProcessExecutionError):
        docker("inspect", container_id)


def test_container_env_hidden_raw_paths(proxy_factory, secret_container):
    container_id, name = secret_container
    with proxy_factory(CONTAINERS=1, HIDE_CONTAINER_ENV=1):
        api_version = json.loads(_proxy_get("/version")[1])["ApiVersion"]
        # Paths Docker serves as inspect must come back filtered
        for path in (
            f"/containers/{container_id}/json",
            f"/containers/{name}/json",
            f"/v{api_version}/containers/{name}/json",
        ):
            status, body = _proxy_get(path)
            assert status == 200, path
            assert json.loads(body)["Config"]["Env"] == [], path
        # Query strings must still reach Docker
        status, body = _proxy_get(f"/containers/{name}/json?size=1")
        assert status == 200
        assert "SizeRw" in json.loads(body)
        # Unusual spellings must never leak, whatever Docker answers
        for path in (
            f"/containers//{name}/json",
            f"/containers/%2F{name}/json",
            f"/containers/{name}/json/",
            f"/v1.24/containers/{name}/json",
        ):
            status, body = _proxy_get(path)
            assert "hunter2" not in body, path


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
