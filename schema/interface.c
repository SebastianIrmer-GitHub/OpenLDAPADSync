#include <krb5.h>
#include <hdb.h>
#include <kadm5/admin.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CHECK_RET(ret, msg) \
    if (ret) { \
        const char *err_msg = krb5_get_error_message(context, ret); \
        fprintf(stderr, "%s: %s\n", msg, err_msg); \
        krb5_free_error_message(context, err_msg); \
        exit(1); \
    }

int main(int argc, char **argv) {
    kadm5_config_params params;
    krb5_context context;
    void *server_handle;
    kadm5_principal_ent_rec princ;
    krb5_principal krb_principal;
    int ret;
    char *client_name = "admin/admin@REALM.COM";
    char *password = "admin_password";
    char *principal_name = "user@REALM.COM";
    
    memset(&params, 0, sizeof(params));
    
    ret = krb5_init_context(&context);
    CHECK_RET(ret, "krb5_init_context");

    params.mask = KADM5_CONFIG_REALM;
    params.realm = "REALM.COM";

    ret = kadm5_init_with_password(client_name, password, KADM5_ADMIN_SERVICE, &params, KADM5_STRUCT_VERSION, KADM5_API_VERSION_4, &server_handle);
    CHECK_RET(ret, "kadm5_init_with_password");

    ret = krb5_parse_name(context, principal_name, &krb_principal);
    CHECK_RET(ret, "krb5_parse_name");

    ret = kadm5_get_principal(server_handle, krb_principal, &princ, KADM5_PRINCIPAL_NORMAL_MASK);
    CHECK_RET(ret, "kadm5_get_principal");

    printf("Principal: %s\n", principal_name);
    printf("Principal Expiration: %ld\n", princ.princ_expire_time);
    printf("Password Expiration: %ld\n", princ.pw_expiration);
    printf("Last Password Change: %ld\n", princ.last_pwd_change);
    printf("Max Ticket Life: %ld\n", princ.max_life);
    printf("Max Renewable Life: %ld\n", princ.max_renewable_life);

    kadm5_free_principal_ent(server_handle, &princ);
    kadm5_destroy(server_handle);
    krb5_free_principal(context, krb_principal);
    krb5_free_context(context);

    return 0;
}
