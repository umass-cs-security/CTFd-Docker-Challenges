import traceback
from typing import Dict

import werkzeug
import yaml


from CTFd.plugins.docker_challenges.scripts.challenge import DockerChallengeType
from CTFd.plugins.docker_challenges.scripts.func import (
    allowed_file,
    get_repositories,
    VerifyImageInRegistry,
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
        docker = DockerConfig.query.filter_by(id=1).first()
        form = DockerConfigForm()
        if request.method == "POST":
            if docker:
                b = docker
            else:
                b = DockerConfig()
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
                b.ca_cert = ca_cert
            if len(client_cert) != 0:
                b.client_cert = client_cert
            if len(client_key) != 0:
                b.client_key = client_key
            b.hostname = request.form["hostname"]
            b.enginename = request.form["enginename"]
            b.tls_enabled = request.form["tls_enabled"]
            if b.tls_enabled == "True":
                b.tls_enabled = True
            else:
                b.tls_enabled = False
            if not b.tls_enabled:
                b.ca_cert = None
                b.client_cert = None
                b.client_key = None
            try:
                # print(request.form.to_dict(flat=False))
                b.repositories = ",".join(
                    request.form.to_dict(flat=False)["repositories"]
                )
                # print(b.repositories)
            except:
                print(traceback.print_exc())
                b.repositories = None
            db.session.add(b)
            db.session.commit()
            docker = DockerConfig.query.filter_by(id=1).first()
        try:
            repos = get_repositories(docker)
        except:
            print(traceback.print_exc())
            repos = list()
        if len(repos) == 0:
            form.repositories.choices = [("ERROR", "Failed to Connect to Docker")]
        else:
            form.repositories.choices = [(d, d) for d in repos]
        dconfig = DockerConfig.query.first()
        try:
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
        target_challenge_name = request.args.get("name", "").lower()

        if target_challenge_name != "":
            ok, target_challenge_name, error_msg = VerifyImageInRegistry(
                docker_config, target_challenge_name
            )
            if not ok:
                # if not ok, just consider this as invalid status query, i.e., return no result
                return render_template("admin_docker_status.html", dockers=[])

        for curr_tracked_challenge in docker_tracker:
            curr_tracked_challenge: DockerChallengeTracker
            if target_challenge_name != "":
                if curr_tracked_challenge.docker_image == target_challenge_name:
                    target = curr_tracked_challenge.__dict__.copy()
                    setattr(target, "requested", True)
                    return render_template("admin_docker_status.html", dockers=[target])
                else:
                    continue
            if is_teams_mode():
                name = Teams.query.filter_by(id=curr_tracked_challenge.team_id).first()
                curr_tracked_challenge.team_id = name.name
            else:
                name = Users.query.filter_by(id=curr_tracked_challenge.user_id).first()
                curr_tracked_challenge.user_id = name.name

        if target_challenge_name != "":
            return render_template("admin_docker_status.html", dockers=[])

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
        docker = DockerConfig.query.filter_by(id=1).first()
        form = DockerImportForm()
        errors = []
        if request.method == "POST":
            if docker:
                active_docker = docker
            else:
                active_docker = DockerConfig()
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
                        hint.strip()
                        for hint in new_challenge_update_dict["hints"]
                        if hint is not None
                    ]
                    for hint in hints:
                        h = Hints(
                            challenge_id=new_challenge_id,
                            content=hint,
                        )
                        db.session.add(h)
                        db.session.commit()
            except Exception as e:
                errors.append(
                    f"Unexpected Error during creating (updating necessary contents) new challenge: {e}"
                )

        return render_template("admin_docker_import.html", form=form, errors=errors)

    app.register_blueprint(admin_docker_import)
