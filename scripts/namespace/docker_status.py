from CTFd.plugins.docker_challenges.scripts.model import (
    DockerChallengeTracker,
    DockerConfig,
)
from CTFd.plugins.docker_challenges.scripts.func import VerifyImagesInRegistry
from CTFd.utils.decorators import authed_only

from CTFd.utils.user import get_current_team
from CTFd.utils.user import get_current_user
from CTFd.utils.config import is_teams_mode

from flask_restx import Namespace, Resource
from flask import request

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

        target_challenge_names = request.args.get("name", "").lower()
        verified_names = []
        if target_challenge_names != "":
            results = VerifyImagesInRegistry(
                docker, target_challenge_names
            )
            for ok, curr_target_challenge_name, error_msg in results:
                # print(ok, target, error_msg)
                if not ok:
                    # if not ok, ignore current result
                    # return render_template("admin_docker_status.html", dockers=[])
                    continue
                verified_names.append(curr_target_challenge_name)
            if len(verified_names) == 0:
                # no need for filtering as no valid result is returned
                return {"success": False, "data": []}

        if is_teams_mode():
            session = get_current_team()
            tracker = DockerChallengeTracker.query.filter_by(team_id=session.id)
        else:
            session = get_current_user()
            tracker = DockerChallengeTracker.query.filter_by(user_id=session.id)
        data = list()
        for curr_challenge in tracker:
            current_data = {
                    "id": curr_challenge.id,
                    "team_id": curr_challenge.team_id,
                    "user_id": curr_challenge.user_id,
                    "docker_image": curr_challenge.docker_image,
                    "timestamp": curr_challenge.timestamp,
                    "revert_time": curr_challenge.revert_time,
                    "instance_id": curr_challenge.instance_id,
                    "ports": curr_challenge.ports.split(","),
                    "host": str(docker.hostname).split(":")[0],
                }
            if len(verified_names) == 0:
                # need to return all current user info
                data.append( current_data )
            elif curr_challenge.docker_image in verified_names:
                # has valid verified names
                data.append( current_data )

        return {"success": True, "data": data}
