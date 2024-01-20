from CTFd.api import CTFd_API_v1
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.challenges import CHALLENGE_CLASSES
from CTFd.plugins.docker_challenges.scripts.challenge import DockerChallengeType
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


def load(app):
    app.db.create_all()
    CHALLENGE_CLASSES["docker"] = DockerChallengeType
    register_plugin_assets_directory(app, base_path="/plugins/docker_challenges/assets")
    define_docker_admin(app)
    define_docker_status(app)
    define_docker_import(app)
    CTFd_API_v1.add_namespace(docker_namespace, "/docker")
    CTFd_API_v1.add_namespace(container_namespace, "/container")
    CTFd_API_v1.add_namespace(active_docker_namespace, "/docker_status")
    CTFd_API_v1.add_namespace(kill_container_namespace, "/nuke")
    # CTFd_API_v1.add_namespace(docker_import_namespace, "/docker_import")
