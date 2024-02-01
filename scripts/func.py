import json
import tempfile
import traceback
from typing import Any, Dict, Tuple
import requests

from CTFd.plugins.docker_challenges.scripts.const import (
    ADMINISTRATIVE,
    ALLOWED_EXTENSIONS,
    IMAGE_NOT_EXIST,
    INVALID_FORMAT,
    INVALID_REGISTRY_SPECIFIED,
    REGISTRY_EMPTY,
)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def dict_to_query_param(inputs: Dict[str, Any]) -> str:
    return "?" + "&".join([f"{key}={value}" for key, value in inputs.items()])


def VerifyImageInRegistry(docker, target_container_name: str) -> Tuple[bool, str, str]:
    """
    return (
        whether image in registry,
        image name if necessary,
        error msg,
    )
    """
    target_container_name = target_container_name.lower()
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
        return (
            target_container_name in fetched_repos,
            target_container_name,
            IMAGE_NOT_EXIST + " " + ADMINISTRATIVE,
        )
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
        res = http_func(**req_params)
    except:
        print(traceback.print_exc())
        res = []
    return res