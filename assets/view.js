CTFd._internal.challenge.data = undefined;

// TODO: Remove in CTFd v4.0
CTFd._internal.challenge.renderer = null;

CTFd._internal.challenge.preRender = function () { };

// TODO: Remove in CTFd v4.0
CTFd._internal.challenge.render = null;

CTFd._internal.challenge.postRender = function () { };


CTFd._internal.challenge.submit = function (preview) {
    var challenge_id = parseInt($("#challenge-id").val());
    var submission = $("#challenge-input").val();

    var body = {
        challenge_id: challenge_id,
        submission: submission
    };
    var params = {};
    if (preview) {
        params["preview"] = true;
    }

    return CTFd.api.post_challenge_attempt(params, body).then(function (response) {
        if (response.status === 429) {
            // User was ratelimited but process response
            return response;
        }
        if (response.status === 403) {
            // User is not logged in or CTF is paused.
            return response;
        }
        return response;
    });
};


function get_docker_status(container) {
    $.get("/api/v1/docker_status", function (result) {
        $.each(result['data'], function (i, item) {
            if (item.docker_image == container) {
                var ports = String(item.ports).split(',');
                var data = '';
                $.each(ports, function (x, port) {
                    port = String(port)
                    data = data + 'Host: ' + item.host + ' Port: ' + port + '<br />';
                })
                $('#docker_container').html('<pre>Docker Container Information:<br />' + data + '<div class="mt-2" id="' + String(item.instance_id).substring(0, 10) + '_revert_container"></div>');
                var countDownDate = new Date(parseInt(item.revert_time) * 1000).getTime();
                var x = setInterval(function () {
                    var now = new Date().getTime();
                    var distance = countDownDate - now;
                    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                    var seconds = Math.floor((distance % (1000 * 60)) / 1000);
                    if (seconds < 10) {
                        seconds = "0" + seconds
                    }
                    $("#" + String(item.instance_id).substring(0, 10) + "_revert_container").html('Next Revert Available in ' + minutes + ':' + seconds);
                    if (distance < 0) {
                        clearInterval(x);
                        $("#" + String(item.instance_id).substring(0, 10) + "_revert_container").html('<a onclick="start_container(\'' + item.docker_image + '\');" class=\'btn btn-dark\'><small style=\'color:white;\'><i class="fas fa-redo"></i> Revert</small></a>');
                    }
                }, 1000);
                return false;
            };
        });
    });
};

const error_template = (error) => {
    return ('<div class="alert alert-danger alert-dismissable" role="alert">' +
    '<span class="sr-only">Error:</span>'+
    error + 
    '<button type="button" class="close" data-dismiss="alert" aria-label="Close">'+
    '<span aria-hidden="true">x</span></button>'+
    '</div>'
    )
}

function show_error(errors) {
//     {% for error in errors %}
// <div class="alert alert-danger alert-dismissable" role="alert">
//     <span class="sr-only">Error:</span>
//     {{ error }}
//     <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span
//             aria-hidden="true">x</span></button>
// </div>
// {% endfor %}
    // remove previous errors
    var error_node = $("#docker_error");
    error_node.hide()
    while (error_node.firstChild) {
        error_node.removeChild(error_node.lastChild);
    }

    for (var error of errors) {
        curr_node = error_template(error);
        error_node.append(curr_node);
        var curr_obj = $(curr_node);
        curr_obj.show();
    }
    error_node.show();
}

function start_container(container) {
    $('#docker_container').html('<div class="text-center"><i class="fas fa-circle-notch fa-spin fa-1x"></i></div>');
    // console.log(container)
    $.get("/api/v1/container", { 'name': container })
    .done(function (result) {
        // console.log(result)
        get_docker_status(container);
        // ezal({
        //     title: "Attention!",
        //     body: "You can only revert a container once per 5 minutes! Please be patient.",
        //     button: "Got it!"
        // });
        // $(get_docker_status(container));
        // get_docker_status(container);
    }).fail(function (jqXHR, textStatus, errorThrown) {
        // console.log(jqXHR.status)
        // console.log(jqXHR.responseJSON)
        ezal({
            title: "Attention!",
            body: jqXHR.responseJSON["message"],
            button: "Got it!"
        });
    });
}

const req_fail_msg = (title, body) => {
    return ('<div class="modal fade" tabindex="-1" role="dialog">' +
        '  <div class="modal-dialog" role="document">' +
        '    <div class="modal-content">' +
        '      <div class="modal-header">' +
        `        <h5 class="modal-title">${title}</h5>` +
        '        <button type="button" class="close" data-dismiss="modal" aria-label="Close">' +
        '          <span aria-hidden="true">&times;</span>' +
        "        </button>" +
        "      </div>" +
        '      <div class="modal-body">' +
        `        <p>${body}</p>` +
        "      </div>" +
        '      <div class="modal-footer">' +
        "      </div>" +
        "    </div>" +
        "  </div>" +
        "</div>")
};

function ezal(args) {
    var res = req_fail_msg(args.title, args.body);
    console.log(res, args)
    var obj = $(res);
    var button = `<button type="button" class="btn btn-primary" data-dismiss="modal">${args.button}</button>`;
    obj.find(".modal-footer").append(button);
    $("main").append(obj);

    obj.modal("show");

    $(obj).on("hidden.bs.modal", function (e) {
        $(this).modal("dispose");
    });

    return obj;
}