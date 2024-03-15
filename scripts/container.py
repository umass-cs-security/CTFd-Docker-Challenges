import hashlib
import json
import random

import flask

from CTFd.plugins.docker_challenges.scripts.const import (
    DOCKER_CHALLENGES_LABEL,
    Default_Headers,
)
from CTFd.plugins.docker_challenges.scripts.func import (
    dict_to_query_param,
    do_request,
    get_required_ports,
    get_unavailable_ports,
    local_name_reverse_map,
)
from CTFd.plugins.docker_challenges.scripts.model import DockerChallenge


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
        if isinstance(resp, flask.Response):
            msg = resp.json["message"]
        else:
            msg = resp.json()["message"]
        print(f"Fail to Delete container: {container_name}. {msg}")
        return False, msg
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
        if isinstance(resp, flask.Response):
            msg = resp.json["message"]
        else:
            msg = resp.json()["message"]
        return False, msg
    return True, resp


def create_container(docker, image, active_flag, team, team_indexing=None):
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
    container_name = "%s_%s" % (image.split(":")[0], team)
    assigned_ports = dict()
    unavailable_ports = get_unavailable_ports(docker)
    needed_ports = list(needed_ports)
    # needed_port in format '3000/tcp'
    for needed_port in needed_ports:
        while True:
            assigned_port = random.choice(range(40000, 60000))
            if assigned_port not in unavailable_ports:
                # mapping from needed port on docker container to assigned port on host
                assigned_ports[needed_port] = f"{assigned_port}/tcp"
                unavailable_ports.append(assigned_port)
                break
    while True:
        forwarding_port = random.choice(range(20000, 40000))
        if forwarding_port not in unavailable_ports:
            # always expose port 56156, in case student want to perform reverse shell on target
            needed_ports.append("56156/tcp")
            # forward traffic from 56156 on docker container to forwarding port on host
            assigned_ports["56156/tcp"] = f"{forwarding_port}/tcp"
            break
    ports = dict()
    bindings = dict()
    # tmp_ports = list(assigned_ports.keys())
    for container_port, host_port in assigned_ports.items():
        ports[container_port] = {}
        bindings[container_port] = [{"HostPort": host_port}]

    tmp_hostname = docker.hostname
    # check whether we need to translate ipv4 addr back to localhost
    if "localhost" not in tmp_hostname:
        ok, mapped_hostname = local_name_reverse_map(docker.hostname)
        if ok:
            tmp_hostname = tmp_hostname.replace(mapped_hostname, "localhost")

    data = json.dumps(
        {
            "Image": f"{tmp_hostname}/{image}",  # image is under the registry
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
            "Env": [f"FLAG={active_flag}"],
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

    if create_res.request is not None:
        print(
            create_res.request.method,
            create_res.request.url,
            create_res.status_code,
            create_res.request.body,
        )
    else:
        print(
            "Error! Create container response does not contain request field, possible error(s) occured during the process."
        )
    result = create_res.json()

    create_status_code = create_res.status_code

    if create_status_code == 201:
        ok, resp = start_container(docker, result["Id"])
        if not ok:
            delete_container(docker, container_name)
            return None, resp
        return result, data
    elif create_status_code == 500 or create_status_code == 400:
        # 400: bad parameter, 500: internal error
        delete_container(docker, container_name)
        return (
            None,
            f"{create_status_code} Internal Error. Please contact website administrator or Professor Parviz.\nDetail: {result['message']}",
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
        return create_container(docker, image, active_flag, team, team_indexing)


def create_containers(
    docker, verified_image_names, active_flag, team, team_indexing=None
):
    delete_stopped_containers(docker)
    verified_image_names = verified_image_names.lower().split(",")

    result = []
    err_payload = None
    for curr_image in verified_image_names:
        created_info, payload = create_container(
            docker, curr_image, active_flag, team, team_indexing
        )
        if created_info is None:
            # print("Error during creating container: ", payload)
            err_payload = payload
            break
        result.append((created_info, payload))

    if err_payload is not None:
        delete_stopped_containers(docker)
        return [(None, err_payload)]
    return result
