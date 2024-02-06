from CTFd.models import db
from CTFd.plugins.docker_challenges.scripts.container import delete_containers
from CTFd.plugins.docker_challenges.scripts.model import (
    DockerConfig,
    DockerChallengeTracker,
)
from CTFd.utils.decorators import admins_only

from flask_restx import Namespace, Resource
from flask import request


kill_container_namespace = Namespace("nuke", description="Endpoint to nuke containers")


@kill_container_namespace.route("", methods=["POST", "GET"])
class KillContainerAPI(Resource):
    @admins_only
    def get(self):
        container = request.args.get("container")
        full = request.args.get("all")
        docker_config = DockerConfig.query.filter_by(id=1).first()
        docker_tracker = DockerChallengeTracker.query.all()
        if full == "true":
            for c in docker_tracker:
                delete_containers(docker_config, c.instance_id)
                DockerChallengeTracker.query.filter_by(
                    instance_id=c.instance_id
                ).delete()
                db.session.commit()

        elif container != "null" and container in [
            c.instance_id for c in docker_tracker
        ]:
            delete_containers(docker_config, container)
            DockerChallengeTracker.query.filter_by(instance_id=container).delete()
            db.session.commit()

        else:
            return False
        return True
