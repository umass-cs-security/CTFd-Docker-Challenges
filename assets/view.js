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
    $.get(`/api/v1/docker_status?name=${container}`, function (result) {
        $.each(result['data'], function (i, item) {
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
        });
    });
};


function start_container(container) {
    $('#docker_container').html('<div class="text-center"><i class="fas fa-circle-notch fa-spin fa-1x"></i></div>');
    $.get("/api/v1/container", { 'name': container })
        .done(function (result) {
            get_docker_status(container);
        }).fail(function (jqXHR, textStatus, errorThrown) {
            ezal({
                title: "Attention!",
                body: jqXHR.responseJSON["message"],
                button: "Got it!"
            });
            get_docker_status(container);
        });
}

function ezal(args) {
    $("#error_dialog_title").html(args.title);
    $("#error_dialog_body").html(args.body);
    $("#error_dialog_confirm_btn").html(args.button);
    $("#error_dialog").modal("show");


    $("#error_dialog").on("hidden.bs.modal", function (e) {
        // $(this).modal("dispose");
        $("#error_dialog").model("hide");
    });

    $("#error_dialog_close_btn").click(function (e) {
        $("#error_dialog").modal("hide");
    })

    $("#error_dialog_confirm_btn").click(function (e) {
        $("#error_dialog").modal("hide");
    })

}