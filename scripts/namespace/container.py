from CTFd.models import db
from CTFd.plugins.docker_challenges.scripts.container import (
    create_containers,
    delete_container,
)
from CTFd.plugins.docker_challenges.scripts.func import (
    VerifyImagesInRegistry,
    flag_generator,
    local_name_reverse_map,
)
from CTFd.plugins.docker_challenges.scripts.model import (
    DockerChallengeTracker,
    DockerChallenge,
    DockerConfig,
)
from CTFd.models import Flags
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
        container_names = request.args.get("name")
        if not container_names:
            return abort(403, description="Image Not Specified in Request!")
        docker: DockerConfig = DockerConfig.query.filter_by(id=1).first()
        existing_containers = DockerChallengeTracker.query.all()

        results = VerifyImagesInRegistry(docker, container_names)
        err_msgs = []
        verified_images = []
        for ok, verified_image, error_msg in results:
            if not ok:
                err_msgs.append(error_msg)
                continue
            verified_images.append(verified_image)

        if len(err_msgs) > 0:
            err_msgs = ",\n".join(err_msgs)
            return abort(
                405,
                description=err_msgs,
            )

        verified_image_names = ",".join(verified_images)
        if verified_image_names == "":
            return abort(
                406,
                description=f"No valid image name was specified: {container_names}",
            )

        verified_image_names_with_docker_host = ""
        for verified_image in verified_images:
            curr_verified_image_components = verified_image.split(":")
            # remove the last element which is the tag of the image
            curr_verified_image_name = ":".join(curr_verified_image_components[:-1])

            tmp_hostname = docker.hostname

            # check whether we need to translate ipv4 addr back to localhost
            if "localhost" not in tmp_hostname:
                ok, mapped_hostname = local_name_reverse_map(docker.hostname)
                if ok:
                    tmp_hostname = tmp_hostname.replace(mapped_hostname, "localhost")

            verified_image_names_with_docker_host += (
                f"{tmp_hostname}/{curr_verified_image_name}"
            )

        curr_docker_chal: DockerChallenge = DockerChallenge.query.filter_by(
            docker_image=verified_image_names_with_docker_host
        ).first()
        if curr_docker_chal is None:
            chals = DockerChallenge.query.all()
            contained = ";;".join([elem.docker_image for elem in chals])
            return abort(
                403,
                description=f"Specified images are not selected in docker config: <{container_names}> -> <{verified_image_names_with_docker_host}>\n{contained}",
            )

        generated_flag = ""
        if curr_docker_chal.flags is None or len(curr_docker_chal.flags) == 0:
            generated_flag = flag_generator(size=16)
        else:
            active_static_flag: Flags = curr_docker_chal.flags[0]
            generated_flag = flag_generator(prefix=active_static_flag.content)

        if is_teams_mode():
            session = get_current_team()
            # First we'll delete all old docker containers (+2 hours)
            for i in existing_containers:
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
                .filter_by(docker_image=verified_image_names)
                .first()
            )
        else:
            session = get_current_user()
            for i in existing_containers:
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
                .filter_by(docker_image=verified_image_names)
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
                    docker_image=verified_image_names
                ).delete()
            else:
                DockerChallengeTracker.query.filter_by(user_id=session.id).filter_by(
                    docker_image=verified_image_names
                ).delete()
            db.session.commit()

        create_results = create_containers(
            docker, verified_image_names, generated_flag, session.name
        )
        ports = []
        for created_info, payload in create_results:
            if created_info is None:
                # print("Error during creating container: ", payload)
                return abort(403, payload)
            ports.extend(json.loads(payload)["HostConfig"]["PortBindings"].values())
        print(f"Adding new container: <{verified_image_names}> for <{session.name}>")
        entry = DockerChallengeTracker(
            team_id=session.id if is_teams_mode() else None,
            user_id=session.id if not is_teams_mode() else None,
            challenge_id=curr_docker_chal.id,
            docker_image=verified_image_names,
            container_flag=generated_flag,
            timestamp=unix_time(datetime.utcnow()),
            revert_time=unix_time(datetime.utcnow()) + 300,
            instance_id=created_info["Id"],
            ports=",".join([port[0]["HostPort"] for port in ports]),
            host=str(docker.enginename).split(":")[0],
        )
        print(
            f"Added new container: <{verified_image_names}> for <{session.name}> at {entry.timestamp}"
        )
        db.session.add(entry)
        db.session.commit()
        # db.session.close()
        return True
