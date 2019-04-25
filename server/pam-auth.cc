#include "pam-auth.h"

static int do_conv (int num_msg, const struct pam_message **msgs, struct pam_response **resp, void *password_ptr) {
    char *pass = (char *) malloc(strlen((char *) password_ptr) + 1);
    strcpy(pass, (char *) password_ptr);

    const struct pam_message *m = *msgs;
    struct pam_response *r;

    if (num_msg <= 0 || num_msg >= PAM_MAX_NUM_MSG) {
        *resp = NULL;
        return PAM_CONV_ERR;
    }

    if ((*resp = r = (struct pam_response *) calloc(num_msg, sizeof (struct pam_response))) == NULL)
        return PAM_BUF_ERR;

    for (int i = 0; i < num_msg; i++) {
        if (m->msg == NULL) goto do_clean;
    
        r->resp = NULL;
        r->resp_retcode = 0;

        if (m->msg_style == PAM_TEXT_INFO) continue;
        if (m->msg_style != PAM_PROMPT_ECHO_OFF) goto do_clean;
        if (strcmp("Password: ", m->msg) != 0) goto do_clean;
        r->resp = pass;

        m++;
        r++;
    }

    return PAM_SUCCESS;

do_clean:
    if (*resp == NULL) return PAM_CONV_ERR;
    r = *resp;

    for (int i = 0; i < num_msg; i++, r++) {
        if (r->resp) {
            memset(r->resp, 0, strlen(r->resp));
            free(r->resp);
            r->resp = NULL;
        }
    }
    free(*resp);
    *resp = NULL;
    return PAM_CONV_ERR;
}

bool do_auth (const char *user, const char *pass) {
    struct pam_conv conv = { &do_conv, (void *) pass };

    pam_handle_t *handle;

    if (pam_start("vswitch-tls-port-enum", user, &conv, &handle) != PAM_SUCCESS) return false;
    int ret = pam_authenticate(handle, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
    pam_end(handle, ret);

    return ret == PAM_SUCCESS;
}