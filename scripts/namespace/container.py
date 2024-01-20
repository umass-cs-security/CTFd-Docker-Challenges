from CTFd.models import db
from CTFd.plugins.docker_challenges.scripts.container import (
    create_container,
    delete_container,
)
from CTFd.plugins.docker_challenges.scripts.func import VerifyImageInRegistry
from CTFd.plugins.docker_challenges.scripts.model import (
    DockerChallengeTracker,
    DockerConfig,
)
from CTFd.utils.decorators import authed_only

from CTFd.utils.user import get_current_team
from CTFd.utils.user import get_current_user
from CTFd.utils.config import is_teams_mode

from flask_restx import Namespace, Resource
from flask import request, abort


from CTFd.utils.dates import unix_time
from datetime import datetime
import json


# API
container_namespace = Namespace(
    "container", description="Endpoint to interact with containers"
)


@container_namespace.route("", methods=["POST", "GET"])
class ContainerAPI(Resource):
    @authed_only
    # I wish this was Post... Issues with API/CSRF and whatnot. Open to a Issue solving this.
    def get(self):
        # name should in format of 'dockerImageName:dockerImageTag', such as 'test:latest'
        container = request.args.get("name")
        if not container:
            return abort(403, description="Image Not Specified in Request!")
        docker = DockerConfig.query.filter_by(id=1).first()
        containers = DockerChallengeTracker.query.all()

        ok, container, error_msg = VerifyImageInRegistry(docker, container)
        if not ok:
            return abort(
                405,
                description=error_msg,
            )

        if is_teams_mode():
            session = get_current_team()
            # First we'll delete all old docker containers (+2 hours)
            for i in containers:
                if (
                    int(session.id) == int(i.team_id)
                    and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200
                ):
                    delete_container(docker, i.instance_id)
                    DockerChallengeTracker.query.filter_by(
                        instance_id=i.instance_id
                    ).delete()
                    db.session.commit()
            check = (
                DockerChallengeTracker.query.filter_by(team_id=session.id)
                .filter_by(docker_image=container)
                .first()
            )
        else:
            session = get_current_user()
            for i in containers:
                if (
                    int(session.id) == int(i.user_id)
                    and (unix_time(datetime.utcnow()) - int(i.timestamp)) >= 7200
                ):
                    delete_container(docker, i.instance_id)
                    DockerChallengeTracker.query.filter_by(
                        instance_id=i.instance_id
                    ).delete()
                    db.session.commit()
            # check is none => docker image is running
            check = (
                DockerChallengeTracker.query.filter_by(user_id=session.id)
                .filter_by(docker_image=container)
                .first()
            )
        # If this container is already created, we don't need another one.
        if (
            check != None
            and not (unix_time(datetime.utcnow()) - int(check.timestamp)) >= 300
        ):
            return abort(
                406,
                description="You can only revert a container once per 5 minutes! Please be patient.",
            )
        # The exception would be if we are reverting a box. So we'll delete it if it exists and has been around for more than 5 minutes.
        elif check != None:
            delete_container(docker, check.instance_id)
            if is_teams_mode():
                DockerChallengeTracker.query.filter_by(team_id=session.id).filter_by(
                    docker_image=container
                ).delete()
            else:
                DockerChallengeTracker.query.filter_by(user_id=session.id).filter_by(
                    docker_image=container
                ).delete()
            db.session.commit()
        created_info, payload = create_container(docker, container, session.name)
        if created_info is None:
            # print("Error during creating container: ", payload)
            return abort(403, payload)
        ports = json.loads(payload)["HostConfig"]["PortBindings"].values()
        print(
            f"Adding new container: <{container}>:<{created_info['Id']}> for <{session.name}>"
        )
        entry = DockerChallengeTracker(
            team_id=session.id if is_teams_mode() else None,
            user_id=session.id if not is_teams_mode() else None,
            docker_image=container,
            timestamp=unix_time(datetime.utcnow()),
            revert_time=unix_time(datetime.utcnow()) + 300,
            instance_id=created_info["Id"],
            ports=",".join([port[0]["HostPort"] for port in ports]),
            host=str(docker.enginename).split(":")[0],
        )
        print(
            f"Added new container: <{container}>:<{created_info['Id']}> for <{session.name}> at {entry.timestamp}"
        )
        db.session.add(entry)
        db.session.commit()
        # db.session.close()
        return True
