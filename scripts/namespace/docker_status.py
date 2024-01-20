from CTFd.plugins.docker_challenges.scripts.model import (
    DockerChallengeTracker,
    DockerConfig,
)
from CTFd.utils.decorators import authed_only

from CTFd.utils.user import get_current_team
from CTFd.utils.user import get_current_user
from CTFd.utils.config import is_teams_mode

from flask_restx import Namespace, Resource


active_docker_namespace = Namespace(
    "docker", description="Endpoint to retrieve User Docker Image Status"
)


@active_docker_namespace.route("", methods=["POST", "GET"])
class DockerStatus(Resource):
    """
    The Purpose of this API is to retrieve a public JSON string of all docker containers
    in use by the current team/user.
    """

    @authed_only
    def get(self):
        docker = DockerConfig.query.filter_by(id=1).first()
        if is_teams_mode():
            session = get_current_team()
            tracker = DockerChallengeTracker.query.filter_by(team_id=session.id)
        else:
            session = get_current_user()
            tracker = DockerChallengeTracker.query.filter_by(user_id=session.id)
        data = list()
        for i in tracker:
            data.append(
                {
                    "id": i.id,
                    "team_id": i.team_id,
                    "user_id": i.user_id,
                    "docker_image": i.docker_image,
                    "timestamp": i.timestamp,
                    "revert_time": i.revert_time,
                    "instance_id": i.instance_id,
                    "ports": i.ports.split(","),
                    "host": str(docker.hostname).split(":")[0],
                }
            )
        return {"success": True, "data": data}
