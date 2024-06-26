import json
from typing import Dict, List
from flask import Blueprint
from CTFd.models import (
    ChallengeFiles,
    Challenges,
    Fails,
    Hints,
    Solves,
    Tags,
    db,
    Flags,
)
from CTFd.plugins.challenges import BaseChallenge

from CTFd.plugins.docker_challenges.scripts.func import sanitizing_docker_image_name
from CTFd.plugins.docker_challenges.scripts.container import delete_container
from CTFd.plugins.docker_challenges.scripts.model import (
    DockerChallenge,
    DockerChallengeTracker,
    DockerConfig,
)
from CTFd.plugins.flags import get_flag_class, CTFdStaticFlag
from CTFd.utils.config import is_teams_mode
from CTFd.utils.user import get_current_team
from CTFd.utils.user import get_current_user
from CTFd.utils.uploads import delete_file
from CTFd.utils.user import get_ip


class DockerChallengeType(BaseChallenge):
    id = "docker"
    name = "docker"
    templates = {
        "create": "/plugins/docker_challenges/assets/create.html",
        "update": "/plugins/docker_challenges/assets/update.html",
        "view": "/plugins/docker_challenges/assets/view.html",
    }
    scripts = {
        "create": "/plugins/docker_challenges/assets/create.js",
        "update": "/plugins/docker_challenges/assets/update.js",
        "view": "/plugins/docker_challenges/assets/view.js",
    }
    route = "/plugins/docker_challenges/assets"
    blueprint = Blueprint(
        "docker_challenges",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

    @staticmethod
    def update(challenge, request):
        """
        This method is used to update the information associated with a challenge. This should be kept strictly to the
        Challenges table and any child tables.

        :param challenge:
        :param request:
        :return:
        """
        data: Dict = request.form or request.get_json()

        if "docker_image" in data:
            if data["docker_image"] is None:
                data.pop("docker_image")
            else:
                data["docker_image"] = sanitizing_docker_image_name(
                    data.get("docker_image")
                )
        for attr, value in data.items():
            setattr(challenge, attr, value)

        db.session.commit()
        return challenge

    @staticmethod
    def delete(challenge):
        """
        This method is used to delete the resources used by a challenge.
        NOTE: Will need to kill all containers here

        :param challenge:
        :return:
        """
        Fails.query.filter_by(challenge_id=challenge.id).delete()
        Solves.query.filter_by(challenge_id=challenge.id).delete()
        Flags.query.filter_by(challenge_id=challenge.id).delete()
        files = ChallengeFiles.query.filter_by(challenge_id=challenge.id).all()
        for f in files:
            delete_file(f.id)
        ChallengeFiles.query.filter_by(challenge_id=challenge.id).delete()
        Tags.query.filter_by(challenge_id=challenge.id).delete()
        Hints.query.filter_by(challenge_id=challenge.id).delete()
        DockerChallenge.query.filter_by(id=challenge.id).delete()
        Challenges.query.filter_by(id=challenge.id).delete()
        db.session.commit()

    @staticmethod
    def read(challenge):
        """
        This method is in used to access the data of a challenge in a format processable by the front end.

        :param challenge:
        :return: Challenge object, data dictionary to be returned to the user
        """
        challenge = DockerChallenge.query.filter_by(id=challenge.id).first()
        data = {
            "id": challenge.id,
            "name": challenge.name,
            "value": challenge.value,
            "docker_image": challenge.docker_image,
            "description": challenge.description,
            "category": challenge.category,
            "state": challenge.state,
            "max_attempts": challenge.max_attempts,
            "type": challenge.type,
            "type_data": {
                "id": DockerChallengeType.id,
                "name": DockerChallengeType.name,
                "templates": DockerChallengeType.templates,
                "scripts": DockerChallengeType.scripts,
            },
        }
        return data

    @staticmethod
    def create(request, dict_form=None):
        """
        This method is used to process the challenge creation request.

        :param request:
        :return:
        """
        if dict_form is not None:
            data = dict_form
        else:
            data = request.form or request.get_json()

        data["docker_image"] = sanitizing_docker_image_name(
            data.get("docker_image", None)
        )
        print(json.dumps(data, indent=4))
        challenge = DockerChallenge(**data)
        db.session.add(challenge)
        db.session.commit()
        return challenge

    @staticmethod
    def attempt(challenge, request):
        """
        This method is used to check whether a given input is right or wrong. It does not make any changes and should
        return a boolean for correctness and a string to be shown to the user. It is also in charge of parsing the
        user's input from the request itself.

        :param challenge: The Challenge object from the database
        :param request: The request the user submitted
        :return: (boolean, string)
        """
        data = request.form or request.get_json()
        # print(request.get_json())
        submission = data["submission"].strip()
        flags: List[Flags] = Flags.query.filter_by(challenge_id=challenge.id).all()
        for flag in flags:
            flag_compare_type = get_flag_class(flag.type)
            if flag_compare_type == CTFdStaticFlag:
                flag_compare_type: CTFdStaticFlag
                filter_params = {
                    "challenge_id": challenge.id,
                }

                if is_teams_mode():
                    session = get_current_team()
                    filter_params["team_id"] = session.id
                else:
                    session = get_current_user()
                    filter_params["user_id"] = session.id

                curr_chal: DockerChallengeTracker = (
                    DockerChallengeTracker.query.filter_by(**filter_params).first()
                )
                if curr_chal is None:
                    return False, "Incorrect"
                if flag_compare_type.compare(
                    flag, submission, curr_chal.container_flag
                ):
                    return True, "Correct"
            elif flag_compare_type.compare(flag, submission):
                return True, "Correct"
        return False, "Incorrect"

    @staticmethod
    def solve(user, team, challenge, request):
        """
        This method is used to insert Solves into the database in order to mark a challenge as solved.

        :param team: The Team object from the database
        :param chal: The Challenge object from the database
        :param request: The request the user submitted
        :return:
        """
        data = request.form or request.get_json()
        submission = data["submission"].strip()
        docker = DockerConfig.query.filter_by(id=1).first()
        try:
            if is_teams_mode():
                docker_containers = (
                    DockerChallengeTracker.query.filter_by(
                        docker_image=challenge.docker_image
                    )
                    .filter_by(team_id=team.id)
                    .first()
                )
            else:
                docker_containers = (
                    DockerChallengeTracker.query.filter_by(
                        docker_image=challenge.docker_image
                    )
                    .filter_by(user_id=user.id)
                    .first()
                )
            delete_container(docker, docker_containers.instance_id)
            DockerChallengeTracker.query.filter_by(
                instance_id=docker_containers.instance_id
            ).delete()
        except:
            pass
        solve = Solves(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(req=request),
            provided=submission,
        )
        db.session.add(solve)
        db.session.commit()
        # trying if this solces the detached instance error...
        # db.session.close()

    @staticmethod
    def fail(user, team, challenge, request):
        """
        This method is used to insert Fails into the database in order to mark an answer incorrect.

        :param team: The Team object from the database
        :param chal: The Challenge object from the database
        :param request: The request the user submitted
        :return:
        """
        data = request.form or request.get_json()
        submission = data["submission"].strip()
        wrong = Fails(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(request),
            provided=submission,
        )
        db.session.add(wrong)
        db.session.commit()
        # db.session.close()
