from http.client import HTTPException
import traceback
from typing import Any, Dict, Tuple

import werkzeug
import yaml

from werkzeug import exceptions as WExceptions
from werkzeug.datastructures import FileStorage

from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES, get_chal_class
from CTFd.plugins.flags import get_flag_class
from CTFd.utils.user import get_ip
from CTFd.utils.uploads import delete_file
from CTFd.plugins import register_plugin_assets_directory, bypass_csrf_protection
from CTFd.schemas.tags import TagSchema
from CTFd.models import (
    Comments,
    Topics,
    db,
    ma,
    Challenges,
    Teams,
    Users,
    Solves,
    Fails,
    Flags,
    Files,
    Hints,
    Tags,
    ChallengeFiles,
)
from CTFd.utils.decorators import (
    admins_only,
    authed_only,
    during_ctf_time_only,
    require_verified_emails,
)
from CTFd.utils.decorators.visibility import (
    check_challenge_visibility,
    check_score_visibility,
)
from CTFd.utils.user import get_current_team
from CTFd.utils.user import get_current_user
from CTFd.utils.user import is_admin, authed
from CTFd.utils.config import is_teams_mode
from CTFd.api import CTFd_API_v1
from CTFd.api.v1.scoreboard import ScoreboardDetail
import CTFd.utils.scores
from CTFd.api.v1.challenges import ChallengeList, Challenge
from flask_restx import Namespace, Resource
from flask import (
    Response,
    flash,
    request,
    Blueprint,
    jsonify,
    abort,
    render_template,
    url_for,
    redirect,
    session,
)

# from flask_wtf import FlaskForm
from wtforms import (
    FileField,
    HiddenField,
    RadioField,
    SelectField,
    StringField,
    SelectMultipleField,
)

# from wtforms import TextField, SubmitField, BooleanField, HiddenField, FileField, SelectMultipleField
from wtforms.validators import DataRequired, ValidationError, InputRequired
from werkzeug.utils import secure_filename
import requests
import tempfile
from CTFd.utils.dates import unix_time
from datetime import datetime
import json
import hashlib
import random
from CTFd.plugins import register_admin_plugin_menu_bar

from CTFd.forms import BaseForm
from CTFd.forms.fields import SubmitField
from CTFd.utils.config import get_themes

DOCKER_CHALLENGES_LABEL = "challenge"
Default_Headers = {"Content-Type": "application/json"}

ADMINISTRATIVE = "Please contact Administrator or Professor Parviz for this error!"
REGISTRY_EMPTY = "Registry is Empty! Please contact Administrator or Professor Parviz to add challenge to Registry!"
INVALID_REGISTRY_SPECIFIED = (
    "Invalid Registry Address Specified. Mismatch with the stored record."
)
INVALID_FORMAT = "Invalid Parameter Format Specified."
IMAGE_NOT_EXIST = "Image does not Exist in Docker Registry!"


class DockerConfig(db.Model):
    """
    Docker Config Model. This model stores the config for docker API connections.
    """

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column("hostname", db.String(64), index=True)
    enginename = db.Column("enginename", db.String(64), index=True)
    tls_enabled = db.Column("tls_enabled", db.Boolean, default=False, index=True)
    ca_cert = db.Column("ca_cert", db.String(2200), index=True)
    client_cert = db.Column("client_cert", db.String(2000), index=True)
    client_key = db.Column("client_key", db.String(3300), index=True)
    repositories = db.Column("repositories", db.String(1024), index=True)


class DockerChallengeTracker(db.Model):
    """
    Docker Container Tracker. This model stores the users/teams active docker containers.
    """

    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column("team_id", db.String(64), index=True)
    user_id = db.Column("user_id", db.String(64), index=True)
    docker_image = db.Column("docker_image", db.String(64), index=True)
    timestamp = db.Column("timestamp", db.Integer, index=True)
    revert_time = db.Column("revert_time", db.Integer, index=True)
    instance_id = db.Column("instance_id", db.String(128), index=True)
    ports = db.Column("ports", db.String(128), index=True)
    host = db.Column("host", db.String(128), index=True)


class DockerConfigForm(BaseForm):
    id = HiddenField()
    hostname = StringField(
        "Docker Hostname",
        description="The Hostname/IP and Port of your Docker Registry Server",
    )
    enginename = StringField(
        "Docker Enginename",
        description="The Hostname/IP and Port of your Docker Engine Server",
    )
    tls_enabled = RadioField("TLS Enabled?")
    ca_cert = FileField("CA Cert")
    client_cert = FileField("Client Cert")
    client_key = FileField("Client Key")
    repositories = SelectMultipleField("Repositories")
    submit = SubmitField("Submit")


class DockerImportForm(BaseForm):
    id = HiddenField()
    file = FileField(
        "File",
        description="Meta YAML file for importing the challenge from config file",
    )
    submit = SubmitField("Submit")


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
        for i in docker_tracker:
            if is_teams_mode():
                name = Teams.query.filter_by(id=i.team_id).first()
                i.team_id = name.name
            else:
                name = Users.query.filter_by(id=i.user_id).first()
                i.user_id = name.name
        return render_template("admin_docker_status.html", dockers=docker_tracker)

    app.register_blueprint(admin_docker_status)


ALLOWED_EXTENSIONS = ["yml", "yaml", "xml", "md"]


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


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
                new_challenge_obj = DockerChallengeType.create(
                    None,
                    new_challenge_dict
                    # request={
                    #     "name": "Asymmetrical Encryptions",
                    #     "category": "test",
                    #     "docker_image": "asymmetrical-encryptions:latest",
                    #     "description": "",
                    #     "value": "100",
                    #     "state": "hidden",
                    #     "type": "docker",
                    # }
                )
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
            # for curr_plur_key, curr_model_type in new_challenge_update_dict.items():
            #     curr_singular_key = curr_plur_key[:-1]
            #     curr_content = None
            #     if (
            #         curr_plur_key not in curr_keys
            #         and curr_singular_key not in curr_keys
            #     ):
            #         # skip if both singular and plural key not found
            #         continue
            #     elif curr_plur_key in curr_keys and curr_singular_key in curr_keys:
            #         # if both plural and singular key exist, ignore singular key
            #         # and check whether plural key's content is a list
            #         curr_content = new_challenge_dict[curr_plur_key]
            #         need_to_drop.append(curr_singular_key)
            #     elif curr_singular_key in curr_keys:
            #         # only singular key exist
            #         curr_content = new_challenge_dict[curr_singular_key]
            #         need_to_drop.append(curr_singular_key)
            #     elif curr_plur_key in curr_keys:
            #         curr_content = new_challenge_dict[curr_plur_key]

            #     if curr_content is None:
            #         continue
            #     if not isinstance(curr_content, list):
            #         curr_content = curr_model_type(curr_content)
            #         new_challenge_dict[curr_plur_key] = [curr_content]
            #     else:
            #         new_challenge_dict[curr_plur_key] = curr_content
        # docker_config = DockerConfig.query.filter_by(id=1).first()

        return render_template("admin_docker_import.html", form=form, errors=errors)

    app.register_blueprint(admin_docker_import)


kill_container = Namespace("nuke", description="Endpoint to nuke containers")


@kill_container.route("", methods=["POST", "GET"])
class KillContainerAPI(Resource):
    @admins_only
    def get(self):
        container = request.args.get("container")
        full = request.args.get("all")
        docker_config = DockerConfig.query.filter_by(id=1).first()
        docker_tracker = DockerChallengeTracker.query.all()
        if full == "true":
            for c in docker_tracker:
                delete_container(docker_config, c.instance_id)
                DockerChallengeTracker.query.filter_by(
                    instance_id=c.instance_id
                ).delete()
                db.session.commit()

        elif container != "null" and container in [
            c.instance_id for c in docker_tracker
        ]:
            delete_container(docker_config, container)
            DockerChallengeTracker.query.filter_by(instance_id=container).delete()
            db.session.commit()

        else:
            return False
        return True


def do_request(docker, url, method="GET", host=None, headers=None, **params):
    prefix = "https" if docker.tls_enabled else "http"
    if host is None:
        host = docker.enginename
    url = f"{prefix}://{host}{url}"

    http_func = None
    if method == "GET":
        http_func = requests.get
    elif method == "POST":
        http_func = requests.post
    elif method == "DELETE":
        http_func = requests.delete
    elif method == "PATCH":
        http_func = requests.patch
    elif method == "PUT":
        http_func = requests.put
    else:
        http_func = requests.get

    req_params = {
        "url": url,
        "headers": headers,
    }
    if params is not None:
        req_params.update(params)
    try:
        if docker.tls_enabled:
            cert = get_client_cert(docker)
            tls_params = {
                "cert": cert,
                "verify": False,
            }
            req_params.update(tls_params)
        # print(json.dumps(req_params, indent=4))
        res = http_func(**req_params)
    except:
        print(traceback.print_exc())
        res = []
    return res


def get_client_cert(docker):
    try:
        ca = docker.ca_cert
        client = docker.client_cert
        ckey = docker.client_key
        ca_file = tempfile.NamedTemporaryFile(delete=False)
        ca_file.write(ca)
        ca_file.seek(0)
        client_file = tempfile.NamedTemporaryFile(delete=False)
        client_file.write(client)
        client_file.seek(0)
        key_file = tempfile.NamedTemporaryFile(delete=False)
        key_file.write(ckey)
        key_file.seek(0)
        CERT = (client_file.name, key_file.name)
    except:
        print(traceback.print_exc())
        CERT = None
    return CERT


# For the Docker Config Page. Gets the Current Repositories available on the Docker Server.
def get_repositories(docker, with_tags=False, expected_repos=None):
    # r = do_request(docker, '/images/json?all=1')
    res = do_request(docker, "/v2/_catalog", host=docker.hostname)
    result = list()
    if res is None or "repositories" not in res.json():
        return None

    for curr_repo in res.json()["repositories"]:
        if expected_repos is not None and len(expected_repos) > 0:
            if curr_repo not in expected_repos:
                continue
        if with_tags:
            tag_res = do_request(
                docker, f"/v2/{curr_repo}/manifests/latest", host=docker.hostname
            )
            curr_tag = tag_res.json()["tag"]
            curr_result = f"{curr_repo}:{curr_tag}"
            result.append(curr_result)
        else:
            result.append(curr_repo)

        # if not i['RepoTags'][0].split(':')[0] == '<none>':
        #     if expected_repos is not None and len(expected_repos) > 0:
        #         if not i['RepoTags'][0].split(':')[0] in repos:
        #             continue
        #     if not tags:
        #         result.append(i['RepoTags'][0].split(':')[0])
        #     else:
        #         result.append(i['RepoTags'][0])
    return list(set(result))


def get_unavailable_ports(docker):
    r = do_request(
        docker,
        "/containers/json?all=1",
        host=docker.enginename,
        headers={"Content-Type": "application/json"},
    )
    result = list()
    for i in r.json():
        if not i["Ports"] == []:
            for p in i["Ports"]:
                result.append(p["PublicPort"])
    return result


def get_required_ports(docker, image):
    # image should in format 'imageName:imagTag'
    repo_name, repo_tag = image.split(":")
    # r = do_request(docker, f'/images/{image}/json?all=1')
    res = do_request(
        docker, f"/v2/{repo_name}/manifests/{repo_tag}", host=docker.hostname
    )
    if res is None or not hasattr(res, "json"):
        return
    res = res.json()
    if "history" not in res:
        return
    for possible_entry in res["history"]:
        curr_content = possible_entry["v1Compatibility"]
        if "ExposedPorts" not in curr_content:
            continue
        curr_content_json = json.loads(curr_content)
        return curr_content_json["config"]["ExposedPorts"].keys()
    # result = r.json()['ContainerConfig']['ExposedPorts'].keys()
    return


def dict_to_query_param(inputs: Dict[str, Any]) -> str:
    return "?" + "&".join([f"{key}={value}" for key, value in inputs.items()])


def start_container(docker, container_name, headers=None):
    if headers is None:
        headers = Default_Headers

    start_res = do_request(
        docker,
        url=f"/containers/{container_name}/start",
        method="POST",
        host=docker.enginename,
        headers=headers,
    )
    if start_res.status_code not in [204, 304]:
        return False, start_res.json()["message"]
    return True, start_res


def delete_container(docker, container_name, headers=None):
    query_param = {
        "force": True,
    }
    if headers is None:
        headers = Default_Headers

    print(f"Deleting container: {container_name}")
    resp = do_request(
        docker,
        url=f"/containers/{container_name}{dict_to_query_param(query_param)}",
        method="DELETE",
        host=docker.enginename,
        headers=headers,
    )
    if resp.status_code == 500:
        print(f"Fail to Delete container: {container_name}. {resp.json()['message']}")
        return False, resp.json()["message"]
    print(f"Deleted container: {container_name}")
    return True, resp


def delete_stopped_containers(docker, headers=None):
    if headers is None:
        headers = Default_Headers
    resp = do_request(
        docker,
        url=f"/containers/prune",
        method="POST",
        host=docker.enginename,
        data={"label": DOCKER_CHALLENGES_LABEL},
        headers=headers,
    )
    if resp.status_code == 500:
        return False, resp.json()["message"]
    return True, resp


# referred api: https://docs.docker.com/engine/api/v1.43/#tag/Container/operation/ContainerCreate
def create_container(docker, image, team, team_indexing=None):
    delete_stopped_containers(docker)
    needed_ports = get_required_ports(docker, image)
    if needed_ports is None:
        return None, "No port(s) exposed, Please re-check the host docker image!"
    if team_indexing == None:
        team = hashlib.md5(team.encode("utf-8")).hexdigest()[:10]
    else:
        if team_indexing + 10 >= 32:
            team_indexing = 22
        team = hashlib.md5(team.encode("utf-8")).hexdigest()[
            team_indexing : team_indexing + 10
        ]
    container_name = "%s_%s" % (image.split(":")[1], team)
    assigned_ports = dict()
    for i in needed_ports:
        while True:
            assigned_port = random.choice(range(30000, 60000))
            if assigned_port not in get_unavailable_ports(docker):
                assigned_ports["%s/tcp" % assigned_port] = {}
                break
    ports = dict()
    bindings = dict()
    tmp_ports = list(assigned_ports.keys())
    for i in needed_ports:
        ports[i] = {}
        bindings[i] = [{"HostPort": tmp_ports.pop()}]
    data = json.dumps(
        {
            "Image": f"{docker.hostname}/{image}",  # image is under the registry
            "ExposedPorts": ports,
            "HostConfig": {
                "PortBindings": bindings,
                "NanoCpus": 1000,
                "Memory": 209715200,
            },
            "Config": {
                "Labels": {
                    "Type": DOCKER_CHALLENGES_LABEL,
                },
            },
        }
    )
    # r = requests.post(
    #     url="%s/containers/create?name=%s" % (URL_TEMPLATE, container_name),
    #     cert=CERT,
    #     verify=False,
    #     data=data,
    #     headers=headers,
    # )
    # create_res = do_request(
    #     docker,
    #     url=f"/containers/create?name={container_name}",
    #     method="POST",
    #     host=docker.enginename,
    #     headers=headers,
    #     data=data,
    # )
    # result = create_res.json()
    # start_res = do_request(
    #     docker,
    #     url=f"/containers/{result['Id']}/start",
    #     # url=f"/containers/create?name={container_name}",
    #     method="POST",
    #     host=docker.enginename,
    #     headers=headers,
    # )
    # requests.post(
    #     url=f"/containers/{result['Id']}/start",
    #     cert=CERT,
    #     verify=False,
    #     headers=headers,
    # )
    # r = requests.post(
    #     url="%s/containers/create?name=%s" % (URL_TEMPLATE, container_name),
    #     data=data,
    #     headers=headers,
    # )
    create_res = do_request(
        docker,
        url=f"/containers/create?name={container_name}",
        method="POST",
        host=docker.enginename,
        headers=Default_Headers,
        data=data,
    )
    print(
        create_res.request.method,
        create_res.request.url,
        create_res.status_code,
        create_res.request.body,
    )
    result = create_res.json()

    create_status_code = create_res.status_code

    print(result)
    if create_status_code == 201:
        ok, resp = start_container(docker, result["Id"])
        print(resp)
        if not ok:
            delete_container(docker, container_name)
            return None, resp
        # do_request(
        #     docker,
        #     url=f"/containers/{result['Id']}/start",
        #     # url=f"/containers/create?name={container_name}",
        #     method="POST",
        #     host=docker.enginename,
        #     headers=headers,
        # )
        return result, data
    elif create_status_code == 500 or create_status_code == 400:
        # 400: bad parameter, 500: internal error
        delete_container(docker, container_name)
        return (
            None,
            f"{create_status_code} Internal Error. Please contact website administrator or Professor Parviz.",
        )
    elif create_status_code == 404:
        # 404: Image not found
        delete_container(docker, container_name)
        return None, result["message"]
    else:
        # 409: name conflit => solve by calling function again
        if team_indexing == None:
            team_indexing = 0
        # increment md5 index by one to avoid name conflit
        team_indexing += 1
        return create_container(docker, image, team, team_indexing)
    # name conflicts are not handled properly
    # print(r.request.method, r.request.url, r.request.body)
    # result = r.json()
    # print(result)
    # # name conflicts are not handled properly
    # s = requests.post(
    #     url="%s/containers/%s/start" % (URL_TEMPLATE, result["Id"]), headers=headers
    # )
    # return result, data


# def delete_container(docker, instance_id):
#     headers = {"Content-Type": "application/json"}
#     do_request(
#         docker,
#         f"/containers/{instance_id}?force=true",
#         host=docker.enginename,
#         headers=headers,
#         method="DELETE",
#     )
#     return True


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
        data = request.form or request.get_json()
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
        # print(data)
        submission = data["submission"].strip()
        flags = Flags.query.filter_by(challenge_id=challenge.id).all()
        for flag in flags:
            if get_flag_class(flag.type).compare(flag, submission):
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


class DockerChallenge(Challenges):
    __mapper_args__ = {"polymorphic_identity": "docker"}
    id = db.Column(None, db.ForeignKey("challenges.id"), primary_key=True)
    docker_image = db.Column(db.String(128), index=True)


# API
container_namespace = Namespace(
    "container", description="Endpoint to interact with containers"
)


def VerifyImageInRegistry(docker, target_container_name: str) -> Tuple[bool, str, str]:
    """
    return (
        whether image in registry,
        image name if necessary,
        error msg,
    )
    """
    fetched_repos = get_repositories(docker, with_tags=True)
    if fetched_repos is None or len(fetched_repos) == 0:
        return False, None, REGISTRY_EMPTY

    if "/" not in target_container_name:
        # name in format of 'dockerImageName:dockerImageTag', such as 'test:latest'
        return (
            target_container_name in fetched_repos,
            target_container_name,
            IMAGE_NOT_EXIST + " " + ADMINISTRATIVE,
        )

    # in format of 'docker registry:registry port/image:image tag'
    target_container_name_components = target_container_name.split("/")
    target_registry_name = "/".join(target_container_name_components[:-1])

    if target_registry_name != docker.hostname:
        return (False, None, INVALID_REGISTRY_SPECIFIED + " " + ADMINISTRATIVE)

    target_container_name = target_container_name_components[-1]

    image_tag = target_container_name.split(":")
    if len(image_tag) == 2:
        return target_container_name in fetched_repos, target_container_name
    elif len(image_tag) != 1:
        return (
            False,
            None,
            f"{INVALID_FORMAT} Image should in format of '<docker image name>:<docker image tag>'. {ADMINISTRATIVE}",
        )
    # only one element, assume to be image name without tag
    target_image = image_tag[0]
    for repo_tag in fetched_repos:
        if target_image in repo_tag:
            return True, repo_tag, None
    return (False, None, IMAGE_NOT_EXIST + " " + ADMINISTRATIVE)


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
    # CTFd_API_v1.add_namespace(docker_import_namespace, "/docker_import")
    CTFd_API_v1.add_namespace(kill_container, "/nuke")
