var csrftoken = $('meta[name=csrf-token]').attr('content');

$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!/^(GET|POST|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken)
        }
    }
});

var LOCK_STATES = {
    UNLOCKED: 0,
    LOCKED:   1,
    PENDING:  2,
}

var lock_states = {};

function set_lock_state(lock_id, state) {
    if(lock_states[lock_id] != state) {
        lock_states[lock_id] = state;
        switch(state) {
        case LOCK_STATES.LOCKED:
            $("button[name='lock-"+lock_id+"']").removeClass("btn-default").removeClass("btn-warning").removeClass("btn-success").addClass("btn-danger").html("<i class='fa fa-lock'></i>").prop('disabled', false);
            $("button[name='lock-"+lock_id+"']").off("click").click(function() {
                unlock(lock_id);
            });
            break;
        case LOCK_STATES.UNLOCKED:
            $("button[name='lock-"+lock_id+"']").removeClass("btn-default").removeClass("btn-warning").removeClass("btn-danger").addClass("btn-success").html("<i class='fa fa-unlock'></i>").prop('disabled', false);
            $("button[name='lock-"+lock_id+"']").off("click").click(function() {
                lock(lock_id);
            });
            break;
        case LOCK_STATES.PENDING:
            $("button[name='lock-"+lock_id+"']").removeClass("btn-default").removeClass("btn-success").removeClass("btn-danger").addClass("btn-warning").html("<i class='fa fa-cog fa-spin'></i>").prop('disabled', true);
            $("button[name='lock-"+lock_id+"']").off("click");
            break;
        default:
            throw RangeError("lock state "+state+" not recognised.");
            break;
        }
    }
}

function check_lock_status(lock_id) {
    var response = $.ajax({ type: "GET",   
                            url: "/status/"+lock_id,
                            async: false,
                            success : function(data, status, xhr) {
                                // console.log(data);
                                // console.log(status);
                                // console.log(xhr);
                            },
                          });
    var data = JSON.parse(response.responseText);
    if ((data.requested_open && !data.actually_open) || (!data.requested_open && data.actually_open)) {
        return LOCK_STATES.PENDING;
    } else {
        if (data.actually_open) {
            return LOCK_STATES.UNLOCKED;
        } else {
            return LOCK_STATES.LOCKED;
        }
    }
}

function update_lock_state(lock_id) {
    var state = check_lock_status(lock_id);
    console.log("Checking...");
    switch(state) {
        case LOCK_STATES.LOCKED:
            setTimeout(function() { update_lock_state(lock_id) }, 3000);
            set_lock_state(lock_id, LOCK_STATES.LOCKED);
            break;
        case LOCK_STATES.UNLOCKED:
            setTimeout(function() { update_lock_state(lock_id) }, 3000);
            set_lock_state(lock_id, LOCK_STATES.UNLOCKED);
            break;
        case LOCK_STATES.PENDING:
            setTimeout(function() { update_lock_state(lock_id) }, 1000);
            set_lock_state(lock_id, LOCK_STATES.PENDING);
            break;
        default:
            throw RangeError("lock state "+state+" not recognised.");
            break;
    }
}

function unlock(lock_id) {
    console.log("Unlocking!");
    $.ajax({ type: "POST",
             url: "/open/"+lock_id,
             async: true,
             success : [
                 function(data, status, xhr) {
                     // console.log(xhr);
                     set_lock_state(lock_id, LOCK_STATES.PENDING);
                 },
                 function() {
                     update_lock_state(lock_id);
                 }
             ],
           });
}

function lock(lock_id) {
    console.log("Locking!");
    $.ajax({ type: "POST",
             url: "/close/"+lock_id,
             async: true,
             success : [
                 function(data, status, xhr) {
                     //console.log(xhr);
                     set_lock_state(lock_id, LOCK_STATES.PENDING);
                 },
                 function() {
                     update_lock_state(lock_id);
                 }
             ],
           });
}
