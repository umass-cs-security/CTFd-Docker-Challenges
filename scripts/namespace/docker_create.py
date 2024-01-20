from CTFd.plugins.docker_challenges.scripts.func import get_repositories
from CTFd.plugins.docker_challenges.scripts.model import DockerConfig

from flask_restx import Namespace, Resource

from CTFd.utils.decorators import admins_only


docker_namespace = Namespace("docker", description="Endpoint to retrieve dockerstuff")


@docker_namespace.route("", methods=["POST", "GET"])
class DockerAPI(Resource):
    """
    This is for creating Docker Challenges. The purpose of this API is to populate the Docker Image Select form
    object in the Challenge Creation Screen.
    """

    @admins_only
    def get(self):
        docker = DockerConfig.query.filter_by(id=1).first()
        images = get_repositories(
            docker, with_tags=True, expected_repos=docker.repositories
        )
        if images:
            data = list()
            for i in images:
                data.append({"name": i})
            return {"success": True, "data": data}
        else:
            return {
                "success": False,
                "data": [{"name": "Error in Docker Config!"}],
            }, 400
