import traceback
from typing import Dict

import werkzeug
import yaml


from CTFd.plugins.docker_challenges.scripts.challenge import DockerChallengeType
from CTFd.plugins.docker_challenges.scripts.func import (
    allowed_file,
    get_repositories,
    VerifyImagesInRegistry,
)
from CTFd.plugins.docker_challenges.scripts.const import (
    ALLOWED_EXTENSIONS,
)
from CTFd.plugins.docker_challenges.scripts.model import (
    DockerConfig,
    DockerChallengeTracker,
    DockerConfigForm,
    DockerImportForm,
)
from CTFd.models import (
    Comments,
    Topics,
    db,
    Teams,
    Users,
    Flags,
    Hints,
    Tags,
    ChallengeFiles,
)
from CTFd.utils.decorators import (
    admins_only,
)

from CTFd.utils.config import is_teams_mode

from flask import (
    request,
    Blueprint,
    render_template,
)


def define_docker_admin(app):
    admin_docker_config = Blueprint(
        "admin_docker_config",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

    @admin_docker_config.route("/admin/docker_config", methods=["GET", "POST"])
    @admins_only
    def docker_config():
        docker: DockerConfig = DockerConfig.query.filter_by(id=1).first()
        form = DockerConfigForm()
        if request.method == "POST":
            if docker is not None:
                active_docker = docker
            else:
                active_docker = DockerConfig()
            try:
                ca_cert = request.files["ca_cert"].stream.read()
            except werkzeug.exceptions.BadRequestKeyError as e:
                print("CA Cert not found.")
            except:
                print(traceback.print_exc())
            finally:
                ca_cert = ""

            try:
                client_cert = request.files["client_cert"].stream.read()
            except werkzeug.exceptions.BadRequestKeyError as e:
                print("Client Cert not found.")
            except:
                print(traceback.print_exc())
            finally:
                client_cert = ""

            try:
                client_key = request.files["client_key"].stream.read()
            except werkzeug.exceptions.BadRequestKeyError as e:
                print("Client Key not found.")
            except:
                print(traceback.print_exc())
            finally:
                client_key = ""

            if len(ca_cert) != 0:
                active_docker.ca_cert = ca_cert
            if len(client_cert) != 0:
                active_docker.client_cert = client_cert
            if len(client_key) != 0:
                active_docker.client_key = client_key
            active_docker.hostname = request.form["hostname"]
            active_docker.enginename = request.form["enginename"]
            active_docker.tls_enabled = request.form["tls_enabled"]
            if active_docker.tls_enabled == "True":
                active_docker.tls_enabled = True
            else:
                active_docker.tls_enabled = False
            if not active_docker.tls_enabled:
                active_docker.ca_cert = None
                active_docker.client_cert = None
                active_docker.client_key = None
            try:
                # print(request.form.to_dict(flat=False))
                dict_result = request.form.to_dict(flat=False)
                if "repositories" in dict_result:
                    active_docker.repositories = ",".join(
                        request.form.to_dict(flat=False)["repositories"]
                    )
                else:
                    active_docker.repositories = ""
                # print(active_docker.repositories)
            except:
                print(traceback.print_exc())
                active_docker.repositories = None
            db.session.add(active_docker)
            db.session.commit()
            docker = DockerConfig.query.filter_by(id=1).first()
        
        repos = []
        try:
            repos = get_repositories(docker)
        except:
            print(traceback.print_exc())
        if len(repos) == 0:
            form.repositories.choices = [("ERROR", "Failed to Connect to Docker")]
        else:
            form.repositories.choices = [(d, d) for d in repos]
        dconfig = DockerConfig.query.first()
        try:
            if dconfig is None:
                selected_repos = list()
            else:
                selected_repos = dconfig.repositories
                if selected_repos == None:
                    selected_repos = list()
        # selected_repos = dconfig.repositories.split(',')
        except:
            print(traceback.print_exc())
            selected_repos = []
        return render_template(
            "docker_config.html", config=dconfig, form=form, repos=selected_repos
        )

    app.register_blueprint(admin_docker_config)


def define_docker_status(app):
    admin_docker_status = Blueprint(
        "admin_docker_status",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

    @admin_docker_status.route("/admin/docker_status", methods=["GET", "POST"])
    @admins_only
    def docker_admin():
        docker_config = DockerConfig.query.filter_by(id=1).first()
        docker_tracker = DockerChallengeTracker.query.all()
        target_challenge_names = request.args.get("name", "").lower()

        verified_names = []
        if target_challenge_names != "":
            results = VerifyImagesInRegistry(docker_config, target_challenge_names)
            for ok, curr_target_challenge_name, error_msg in results:
                # print(ok, target, error_msg)
                if not ok:
                    # if not ok, ignore current result
                    # return render_template("admin_docker_status.html", dockers=[])
                    continue
                verified_names.append(curr_target_challenge_name)
            if len(verified_names) == 0:
                # no need for filtering as no valid result is returned
                return render_template("admin_docker_status.html", dockers=[])
        verified_dockers = []
        for curr_tracked_challenge in docker_tracker:
            curr_tracked_challenge: DockerChallengeTracker
            if len(verified_names) > 0:
                if curr_tracked_challenge.docker_image in verified_names:
                    # target = curr_tracked_challenge.__dict__.copy()
                    # setattr(target, "requested", True)
                    verified_dockers.append(curr_tracked_challenge)
                else:
                    continue
            if is_teams_mode():
                name = Teams.query.filter_by(id=curr_tracked_challenge.team_id).first()
                curr_tracked_challenge.team_id = name.name
            else:
                name = Users.query.filter_by(id=curr_tracked_challenge.user_id).first()
                curr_tracked_challenge.user_id = name.name

        if len(verified_names) > 0:
            return render_template("admin_docker_status.html", dockers=verified_dockers)

        return render_template("admin_docker_status.html", dockers=docker_tracker)

    app.register_blueprint(admin_docker_status)


def define_docker_import(app):
    admin_docker_import = Blueprint(
        "admin_docker_import",
        __name__,
        template_folder="templates",
        static_folder="assets",
    )

    @admin_docker_import.route("/admin/docker_import", methods=["GET", "POST"])
    @admins_only
    def docker_import():
        active_docker = DockerConfig.query.filter_by(id=1).first()
        form = DockerImportForm()
        errors = []
        if request.method == "POST":
            if active_docker is None or active_docker.repositories is None:
                errors.append(
                    "No valid docker registry configured, please check docker config!"
                )
                return render_template(
                    "admin_docker_import.html",
                    form=form,
                    errors=errors,
                )

            repos = list()
            if active_docker.repositories is not None:
                repos = active_docker.repositories.split(",")
            if len(repos) == 0:
                errors.append(
                    "No valid repository selected in docker config. "
                    + "Please select at least one valid repository!"
                )

            try:
                meta_yaml_obj = request.files["meta_importer"]
                if not meta_yaml_obj or not allowed_file(meta_yaml_obj.filename):
                    errors.append(
                        "File Type not Allowed. "
                        + f"Allowed Type(s): [{','.join(ALLOWED_EXTENSIONS)}]"
                    )
            except werkzeug.exceptions.BadRequestKeyError as e:
                errors.append("YAML File is invalid or not found.")
            except Exception as e:
                errors.append(f"Unexpected Error: {e}")
            finally:
                if len(errors) != 0:
                    print(traceback.print_exc())
                    return render_template(
                        "admin_docker_import.html",
                        form=form,
                        errors=errors,
                    )

            try:
                new_challenge_dict: Dict[str, str] = yaml.safe_load(meta_yaml_obj)
            except yaml.YAMLError as e:
                errors.append(f"Unexpected Error during parsing meta file: {e}")
            except Exception as e:
                errors.append(f"Unexpected Error: {e}")
            finally:
                if len(errors) != 0:
                    print(traceback.print_exc())
                    return render_template(
                        "admin_docker_import.html",
                        form=form,
                        errors=errors,
                    )

            allowed_attrs = [
                "name",
                "docker_image",
                "description",
                "connection_info",
                "next_id",
                "value",
                "category",
                "type",
                "state",
                "requirements",
            ]
            allowed_attrs_plur_available = {
                "files": ChallengeFiles,
                "tags": Tags,
                "hints": Hints,
                "flags": Flags,
                "comments": Comments,
                "topics": Topics,
            }
            required_attrs = [
                "name",
                "docker_image",
                "description",
                "value",
                "category",
            ]
            required_but_not_exist = required_attrs.copy()
            need_to_drop = []
            new_challenge_update_dict = {}
            curr_keys = new_challenge_dict.keys()
            for key in curr_keys:
                key = key.lower()
                plur_key = f"{key}s"
                if (
                    key not in allowed_attrs
                    and key not in allowed_attrs_plur_available.keys()
                    and plur_key not in allowed_attrs_plur_available.keys()
                ):
                    need_to_drop.append(key)
                    continue

                if key in required_attrs:
                    required_but_not_exist.remove(key)

                if key in new_challenge_update_dict:
                    continue
                if key in allowed_attrs_plur_available.keys():
                    need_to_drop.append(key)
                    curr_content = new_challenge_dict[key]
                    if not isinstance(curr_content, list):
                        curr_content = [curr_content]
                    new_challenge_update_dict[key] = curr_content
                elif plur_key in allowed_attrs_plur_available.keys():
                    need_to_drop.append(key)
                    curr_content = new_challenge_dict[key]
                    if not isinstance(curr_content, list):
                        curr_content = [curr_content]
                    new_challenge_update_dict[plur_key] = curr_content

            if "flag" not in curr_keys and "flags" not in curr_keys:
                required_but_not_exist.append("flag")

            if len(required_but_not_exist) > 0:
                errors.append(
                    f"Need to specify attributes [{', '.join(required_attrs)}]! "
                    + f"Missing following attributes [{', '.join(required_but_not_exist)}]!"
                )
                return render_template(
                    "admin_docker_import.html",
                    form=form,
                    errors=errors,
                )

            for elem in need_to_drop:
                new_challenge_dict.pop(elem, None)
            try:
                new_challenge_obj = DockerChallengeType.create(None, new_challenge_dict)
                new_challenge_id = new_challenge_obj.id
            except Exception as e:
                errors.append(f"Unexpected Error during creating new challenge: {e}")
            finally:
                if len(errors) != 0:
                    print(traceback.print_exc())
                    return render_template(
                        "admin_docker_import.html",
                        form=form,
                        errors=errors,
                    )

            try:
                if (
                    "flags" in new_challenge_update_dict
                    and new_challenge_update_dict["flags"] is not None
                ):
                    flags = [
                        flag.strip()
                        for flag in new_challenge_update_dict["flags"]
                        if flag is not None
                    ]
                    for flag in flags:
                        f = Flags(
                            type="static",
                            challenge_id=new_challenge_id,
                            content=flag,
                        )
                        db.session.add(f)
                        db.session.commit()

                if (
                    "tags" in new_challenge_update_dict
                    and new_challenge_update_dict["tags"] is not None
                ):
                    tags = [
                        tag.strip()
                        for tag in new_challenge_update_dict["tags"]
                        if tag is not None
                    ]
                    for tag in tags:
                        t = Tags(
                            challenge_id=new_challenge_id,
                            value=tag,
                        )
                        db.session.add(t)
                        db.session.commit()

                if (
                    "hints" in new_challenge_update_dict
                    and new_challenge_update_dict["hints"] is not None
                ):
                    hints = [
                        hint
                        for hint in new_challenge_update_dict["hints"]
                        if hint is not None
                    ]
                    for hint in hints:
                        h = Hints(
                            challenge_id=new_challenge_id,
                            content=hint["content"],
                            cost=hint["cost"],
                        )
                        db.session.add(h)
                        db.session.commit()
            except Exception as e:
                print(traceback.print_exc())
                errors.append(
                    f"Unexpected Error during creating (updating necessary contents) new challenge: {e}"
                )

        return render_template("admin_docker_import.html", form=form, errors=errors)

    app.register_blueprint(admin_docker_import)
