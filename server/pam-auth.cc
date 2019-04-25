#include "pam-auth.h"

static int _panconv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    char *pass = (char *) malloc(strlen((char *) appdata_ptr)+1);
    strcpy(pass, (char *) appdata_ptr);

    int i;

    *resp = (pam_response *) calloc(num_msg, sizeof(struct pam_response));

    for (i = 0; i < num_msg; ++i) {
        if (msg[i]->msg_style != PAM_PROMPT_ECHO_OFF) continue;
        resp[i]->resp = pass;
    }

    return PAM_SUCCESS;
}

bool do_auth (const char *user, const char *pass) {
    struct pam_conv conv = { &_panconv, (void *) pass };

    pam_handle_t *handle;
    int authResult;

    pam_start("shutterd", user, &conv, &handle);
    authResult = pam_authenticate(handle, PAM_SILENT|PAM_DISALLOW_NULL_AUTHTOK);
    pam_end(handle, authResult);

    return (authResult == PAM_SUCCESS);
}