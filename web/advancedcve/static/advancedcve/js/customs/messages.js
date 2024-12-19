/**
 * Add a success alert message to the container.
 * @param {*} parent Parent container.
 * @param {*} message Message to display.
 */
function success(parent, message) {
    genericMessage(parent, message, "alert alert-success");
}

/**
 * Add a error alert message to the container.
 * @param {*} parent Parent container.
 * @param {*} message Message to display.
 */
function error(parent, message) {
    genericMessage(parent, message, "alert alert-danger");
}

/**
 * Add error alert messages to the container.
 * @param {*} parent Parent container.
 * @param {*} jsonResponse JSON response from API.
 */
function errorList(parent, jsonResponse) {
    genericMessageList(parent, jsonResponse, "alert alert-danger");
}

/**
 * Clean the messages container.
 * @param {*} container Container to clean.
 */
function cleanMessagesContainer(container) {
    container.empty();
}

/**
 * Generic message. 
 */
function genericMessage(parent, message, alertClass) {
    parent.append($('<div>', { class: alertClass, "role": "alert" }).text(message).append($('<button>', { type: "button", class: "close", "data-dismiss": "alert", "aria-hidden": "true" }).text("×")));
}

/**
 * Generic bulk messages.
 */
function genericMessageList(parent, jsonResponse, alertClass) {
    jQuery.each(jsonResponse, function (param, messages) {
        if (Array.isArray(messages)) {
            jQuery.each(messages, function () {
                genericMessage(parent, param + " : " + this, alertClass);
            });
        } else {
            genericMessage(parent, param + " : " + messages, alertClass);
        }
    });
}

/**
 * Generic failure callback for ajax-common.
 */
function commonFailure(data) {
    if(data.status === 403){
        error($("#messages"), "Error 403 : Not Authorized");
    } else {
        errorList($("#messages"), data.responseJSON);
    }
}
