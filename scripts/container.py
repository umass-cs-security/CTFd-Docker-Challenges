from collections import defaultdict
import hashlib
import json
import random
from CTFd.plugins.docker_challenges.scripts.const import (
    Default_Headers,
    DOCKER_CHALLENGES_LABEL,
)
from CTFd.plugins.docker_challenges.scripts.func import (
    dict_to_query_param,
    do_request,
    get_required_ports,
    get_unavailable_ports,
)


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
    if isinstance(resp, str):
        print(f"Fail to Delete container: {container_name}. {resp}")
        return False, resp
    if resp.status_code == 500:
        print(f"Fail to Delete container: {container_name}. {resp.json()['message']}")
        return False, resp.json()["message"]
    print(f"Deleted container: {container_name}")
    return True, resp


def delete_containers(docker, container_names, headers=None):
    container_names = container_names.split(",")

    delete_success = True
    resps = []
    for container_name in container_names:
        ok, resp = delete_container(docker, container_name, headers)
        if not ok:
            delete_success = False
        resps.append(resp)
    return delete_success, resps


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
    if isinstance(resp, str):
        print(f"Fail to Delete stopped container. {resp}")
        return False, resp
    if resp.status_code == 500:
        return False, resp.json()["message"]
    return True, resp


def create_container(docker, image, team, team_indexing=None):
    ok, needed_ports = get_required_ports(docker, image)
    if not ok:
        return None, needed_ports

    unavilable_ports = get_unavailable_ports(docker)
    assigned_ports = defaultdict(dict)
    for curr_port in needed_ports:
        while True:
            assigned_port = random.choice(range(30000, 60000))
            if assigned_port not in unavilable_ports:
                assigned_ports[curr_port] = f"{assigned_port}/tcp"
                break
    if team_indexing == None:
        team = hashlib.md5(team.encode("utf-8")).hexdigest()[:10]
    else:
        if team_indexing + 10 >= 32:
            team_indexing = 22
        team = hashlib.md5(team.encode("utf-8")).hexdigest()[
            team_indexing : team_indexing + 10
        ]
    container_name = "%s_%s" % (image.split(":")[0], team)

    ports = dict()
    bindings = dict()
    for curr_port in needed_ports:
        ports[curr_port] = {}
        bindings[curr_port] = [{"HostPort": assigned_ports[curr_port]}]
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
            delete_containers(docker, container_name)
            return None, resp
        return (result, data), None
    elif create_status_code == 500 or create_status_code == 400:
        # 400: bad parameter, 500: internal error
        delete_containers(docker, container_name)
        return (
            None,
            f"{create_status_code} Internal Error. Please contact website administrator or Professor Parviz.",
        )
    elif create_status_code == 404:
        # 404: Image not found
        delete_containers(docker, container_name)
        return None, result["message"]
    else:
        # 409: name conflit => solve by calling function again
        if team_indexing == None:
            team_indexing = 0
        # increment md5 index by one to avoid name conflit
        team_indexing += 1
        return create_container(docker, image, team, team_indexing)


# referred api: https://docs.docker.com/engine/api/v1.43/#tag/Container/operation/ContainerCreate
def create_containers(docker, images, team, team_indexing=None):
    delete_stopped_containers(docker)
    images = images.split(",")
    need_remove = False
    err_msg = ""
    created_infos = dict()
    for image in images:
        curr_result, err_msg = create_container(docker, image, team)
        if curr_result is None:
            need_remove = True
            break
        created_infos[image] = curr_result

    if not need_remove:
        return created_infos, err_msg

    # even if there is only one container went wrong, need to cleanup others
    for key, (info, payload) in created_infos.items():
        delete_containers(docker, info["Id"])
        return None, err_msg
