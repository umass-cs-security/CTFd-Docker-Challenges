from CTFd.api import CTFd_API_v1
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.challenges import CHALLENGE_CLASSES
from CTFd.plugins.docker_challenges.scripts.challenge import DockerChallengeType
from CTFd.plugins.docker_challenges.scripts.model import DockerConfig, db

from CTFd.plugins.docker_challenges.scripts.pages import (
    define_docker_admin,
    define_docker_import,
    define_docker_status,
)
from CTFd.plugins.docker_challenges.scripts.namespace import (
    docker_namespace,
    active_docker_namespace,
    container_namespace,
    kill_container_namespace,
)

import netifaces as ni


def default_docker_config():
    docker = DockerConfig.query.filter_by(id=1).first()
    if docker is not None:
        print("Cannot set defualt config for docker: has existing docker config!")
        return

    if "eth0" not in ni.interfaces():
        print(
            "Cannot set defualt config for docker: default network interface 'eth0' is unavilable!"
        )
        return

    try:
        curr_addr = ni.ifaddresses("eth0")[ni.AF_INET][0]["addr"]
        new_docker = DockerConfig(
            hostname=f"{curr_addr}:56156",
            enginename=f"{curr_addr}:2376",
            tls_enabled=True,
        )
        db.session.add(new_docker)
        db.session.commit()
    except Exception as e:
        print(f"Cannot set defualt config for docker: Unexpected error: {e}")
        return


def load(app):
    app.db.create_all()
    CHALLENGE_CLASSES["docker"] = DockerChallengeType
    register_plugin_assets_directory(app, base_path="/plugins/docker_challenges/assets")
    define_docker_admin(app)
    define_docker_status(app)
    define_docker_import(app)
    default_docker_config()
    CTFd_API_v1.add_namespace(docker_namespace, "/docker")
    CTFd_API_v1.add_namespace(container_namespace, "/container")
    CTFd_API_v1.add_namespace(active_docker_namespace, "/docker_status")
    CTFd_API_v1.add_namespace(kill_container_namespace, "/nuke")
