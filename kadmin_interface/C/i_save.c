#include <Python.h>
#include <krb5.h>
#include <kadm5/admin.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CHECK_RET(ret, context, msg) \
    if (ret) { \
        const char *err_msg = krb5_get_error_message(context, ret); \
        PyErr_Format(PyExc_RuntimeError, "%s: %s", msg, err_msg); \
        krb5_free_error_message(context, err_msg); \
        goto cleanup; \
    }


krb5_error_code init_context_and_creds(krb5_context *context_out, krb5_creds *creds_out, char **client_name_out, void **server_handle_out, char **error_msg) {
    krb5_error_code ret;
    krb5_context context = NULL;
    krb5_principal client_principal = NULL;
    kadm5_config_params params;
    void *server_handle = NULL;
    char *client_name = NULL;
    krb5_keytab keytab = NULL;
    krb5_creds creds;
    krb5_get_init_creds_opt *opts = NULL;

    memset(&params, 0, sizeof(params));
    params.mask = KADM5_CONFIG_REALM;
    params.realm = "KRB";

    ret = krb5_init_context(&context);
    if (ret) {
        *error_msg = strdup("Error initializing context");
        goto cleanup;
    }

    ret = krb5_kt_resolve(context, "admin.keytab", &keytab); // Replace with your keytab file path
    if (ret) {
        *error_msg = strdup("Error resolving keytab");
        goto cleanup;
    }

    ret = krb5_parse_name(context, "admin/admin@KRB", &client_principal); // Replace with your client principal
    if (ret) {
        *error_msg = strdup("Error parsing client principal name");
        goto cleanup;
    }

    ret = krb5_get_init_creds_opt_alloc(context, &opts);
    if (ret) {
        *error_msg = strdup("Error allocating get_init_creds options");
        goto cleanup;
    }

    ret = krb5_get_init_creds_keytab(context, &creds, client_principal, keytab, 0, "admin/admin", opts);
    if (ret) {
        *error_msg = strdup("Error getting initial credentials from keytab");
        goto cleanup;
    }

    ret = krb5_unparse_name(context, client_principal, &client_name);
    if (ret) {
        *error_msg = strdup("Error unparsing client principal name");
        goto cleanup;
    }
    ret = kadm5_init_with_skey(client_name, "admin.keytab", "kadmin/admin", &params, KADM5_STRUCT_VERSION, KADM5_API_VERSION_2, &server_handle);
    if (ret) {
        *error_msg = strdup("Error initializing admin service");
        goto cleanup;
    }
    *context_out = context;
    *creds_out = creds;
    *client_name_out = client_name;
    *server_handle_out = server_handle;

    return 0;

cleanup:
    if (opts) krb5_get_init_creds_opt_free(context, opts);
    if (keytab) krb5_kt_close(context, keytab);
    if (client_name) free(client_name);
    if (client_principal) krb5_free_principal(context, client_principal);
    if (context) krb5_free_context(context);
    return ret;
}

int get_principal_info(const char* principal_name, kadm5_principal_ent_rec *princ_out, void **server_handle_out, const char* keytab_path) {
    krb5_error_code ret;
    krb5_context context = NULL;
    krb5_creds creds_out;
    void *server_handle = NULL;
    krb5_principal krb_principal = NULL;
    char *client_name = NULL;
    char *error_msg = NULL;
    ret = init_context_and_creds(&context, &creds_out, &client_name, &server_handle, &error_msg);
    if (ret) {
        PyErr_Format(PyExc_RuntimeError, "init_context_and_creds failed: %s", error_msg);
        free(error_msg);
        return ret;
    }
    ret = krb5_parse_name(context, principal_name, &krb_principal);
    CHECK_RET(ret, context, "Error parsing principal name");

    ret = kadm5_get_principal(server_handle, krb_principal, princ_out, KADM5_PRINCIPAL_NORMAL_MASK);
    CHECK_RET(ret, context, "Error getting principal");

    *server_handle_out = server_handle;

cleanup:
    if (krb_principal) krb5_free_principal(context, krb_principal);
    if (client_name) free(client_name);
    if (creds_out.client) krb5_free_cred_contents(context, &creds_out);
    if (context) krb5_free_context(context);
    return ret;
}

int delete_principal(const char* principal_name, const char* keytab_path) {
    krb5_error_code ret;
    krb5_context context = NULL;
    krb5_creds creds_out;
    void *server_handle = NULL;
    krb5_principal krb_principal = NULL;
    char *client_name = NULL;
    char *error_msg = NULL;

    ret = init_context_and_creds(&context, &creds_out, &client_name, &server_handle, &error_msg);
    if (ret) {
        PyErr_Format(PyExc_RuntimeError, "init_context_and_creds failed: %s", error_msg);
        free(error_msg);
        return ret;
    }

    ret = krb5_parse_name(context, principal_name, &krb_principal);
    CHECK_RET(ret, context, "Error parsing principal name");

    ret = kadm5_delete_principal(server_handle, krb_principal);
    CHECK_RET(ret, context, "Error deleting principal");

cleanup:
    if (krb_principal) krb5_free_principal(context, krb_principal);
    if (client_name) free(client_name);
    if (creds_out.client) krb5_free_cred_contents(context, &creds_out);
    if (server_handle) kadm5_destroy(server_handle);
    if (context) krb5_free_context(context);
    return ret;
}

int list_principals(char ***principals_out, int *count_out, const char* keytab) {
    krb5_error_code ret;
    krb5_context context = NULL;
    krb5_creds creds;
    void *server_handle = NULL;
    char *client_name = NULL;
    char **principals = NULL;
    int count = 0;
    char *error_msg = NULL;

    ret = init_context_and_creds(&context, &creds, &client_name, &server_handle, &error_msg);
    if (ret) {
        PyErr_Format(PyExc_RuntimeError, "init_context_and_creds failed: %s", error_msg);
        free(error_msg);
        return ret;
    }

    ret = kadm5_get_principals(server_handle, "*", &principals, &count);
    CHECK_RET(ret, context, "Error listing principals");

    *principals_out = principals;
    *count_out = count;

cleanup:
    if (client_name) free(client_name);
    if (creds.client) krb5_free_cred_contents(context, &creds);
    if (context) krb5_free_context(context);
    return ret;
}
int add_principal(const char* principal_name, const char* password, const char* keytab_path, time_t pw_expiration_time, time_t princ_expiration_time, int account_disabled) {
    printf(keytab_path);
    krb5_error_code ret;
    krb5_context context = NULL;
    krb5_creds creds;
    void *server_handle = NULL;
    krb5_principal krb_principal = NULL;
    char *client_name = NULL;
    kadm5_principal_ent_rec princ;
    char *error_msg = NULL;

    ret = init_context_and_creds(&context, &creds, &client_name, &server_handle, &error_msg);
    if (ret) {
        PyErr_Format(PyExc_RuntimeError, "init_context_and_creds failed: %s", error_msg);
        free(error_msg);
        return ret;
    }

    ret = krb5_parse_name(context, principal_name, &krb_principal);
    CHECK_RET(ret, context, "Error parsing principal name");

    memset(&princ, 0, sizeof(princ));
    princ.principal = krb_principal;
    princ.max_life = 0;
    princ.max_renewable_life = 0;
    princ.pw_expiration = pw_expiration_time; 
    princ.princ_expire_time = princ_expiration_time; 

    if (account_disabled) {
        princ.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
    } else  {
        princ.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
   }

    ret = kadm5_create_principal(server_handle, &princ, KADM5_PRINCIPAL | KADM5_PW_EXPIRATION | KADM5_PRINC_EXPIRE_TIME | KADM5_ATTRIBUTES, password);
    CHECK_RET(ret, context, "Error creating principal");

cleanup:
    if (krb_principal) krb5_free_principal(context, krb_principal);
    if (client_name) free(client_name);
    if (creds.client) krb5_free_cred_contents(context, &creds);
    if (server_handle) kadm5_destroy(server_handle);
    if (context) krb5_free_context(context);
    return ret;
}


// Python wrapper function for get_principal_info

int modify_principal(const char* principal_name, const char* keytab_path,  long princ_expiration_time, int account_disabled) {
    krb5_error_code ret;
    krb5_context context = NULL;
    krb5_creds creds;
    void *server_handle = NULL;
    krb5_principal krb_principal = NULL;
    char *client_name = NULL;
    kadm5_principal_ent_rec princ;
    char *error_msg = NULL;

    ret = init_context_and_creds(&context, &creds, &client_name, &server_handle, &error_msg);
    if (ret) {
        PyErr_Format(PyExc_RuntimeError, "init_context_and_creds failed: %s", error_msg);
        free(error_msg);
        return ret;
    }

    ret = krb5_parse_name(context, principal_name, &krb_principal);
    CHECK_RET(ret, context, "Error parsing principal name");

    memset(&princ, 0, sizeof(princ));
    princ.principal = krb_principal;

 
    if (princ_expiration_time > 0) {
        princ.princ_expire_time = princ_expiration_time;
    }
    if (account_disabled) {
        princ.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
    } else  {
        princ.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
   }


   
    ret = kadm5_modify_principal(server_handle, &princ, KADM5_PRINC_EXPIRE_TIME | KADM5_ATTRIBUTES);
    CHECK_RET(ret, context, "Error modifying principal");

cleanup:
    if (krb_principal) krb5_free_principal(context, krb_principal);
    if (client_name) free(client_name);
    if (creds.client) krb5_free_cred_contents(context, &creds);
    if (server_handle) kadm5_destroy(server_handle);
    if (context) krb5_free_context(context);
    return ret;
}

int change_password(const char* principal_name, const char* new_password) {
    krb5_error_code ret;
    krb5_context context = NULL;
    krb5_creds creds;
    void *server_handle = NULL;
    krb5_principal krb_principal = NULL;
    char *client_name = NULL;
    char *error_msg = NULL;

    ret = init_context_and_creds(&context, &creds, &client_name, &server_handle, &error_msg);
    if (ret) {
        PyErr_Format(PyExc_RuntimeError, "init_context_and_creds failed: %s", error_msg);
        free(error_msg);
        return ret;
    }

    ret = krb5_parse_name(context, principal_name, &krb_principal);
    CHECK_RET(ret, context, "Error parsing principal name");

    ret = kadm5_chpass_principal(server_handle, krb_principal, new_password);
    CHECK_RET(ret, context, "Error changing password");

cleanup:
    if (krb_principal) krb5_free_principal(context, krb_principal);
    if (client_name) free(client_name);
    if (creds.client) krb5_free_cred_contents(context, &creds);
    if (server_handle) kadm5_destroy(server_handle);
    if (context) krb5_free_context(context);
    return ret;
}
static PyObject* py_get_principal_info(PyObject* self, PyObject* args) {
    const char* principal_name;
    const char* keytab_path;
    kadm5_principal_ent_rec princ;
    void *server_handle = NULL;
    krb5_creds creds;
    if (!PyArg_ParseTuple(args, "ss", &principal_name, &keytab_path))
        return NULL;

    int ret = get_principal_info(principal_name, &princ, &server_handle, keytab_path);
    if (ret) {
        // Error already set by CHECK_RET
        return NULL;
    }

    PyObject* result = Py_BuildValue(
        "{s:s, s:l, s:l, s:l, s:l, s:l}",
        "principal_name", principal_name,
        "principal_expire_time", princ.princ_expire_time,
        "pw_expiration", princ.pw_expiration,
        "last_pwd_change", princ.last_pwd_change,
        "max_life", princ.max_life,
        "max_renewable_life", princ.max_renewable_life
    );

    kadm5_free_principal_ent(server_handle, &princ);
    kadm5_destroy(server_handle);

    return result;
}
// Python wrapper function for delete_principal
static PyObject* py_delete_principal(PyObject* self, PyObject* args) {
    const char* principal_name;
    const char* keytab_path;

    if (!PyArg_ParseTuple(args, "ss", &principal_name, &keytab_path))
        return NULL;

    int ret = delete_principal(principal_name, keytab_path);
    if (ret) {
        
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject* py_modify_principal(PyObject* self, PyObject* args) {
    const char* principal_name;
    const char* keytab_path;
    long princ_expiration_time;
    int account_disabled;

    if (!PyArg_ParseTuple(args, "ssli", &principal_name, &keytab_path, &princ_expiration_time, &account_disabled))
        return NULL;

    int ret = modify_principal(principal_name, keytab_path, (time_t)princ_expiration_time, account_disabled);
    if (ret) {
        // Error already set by CHECK_RET
        return NULL;
    }

    Py_RETURN_NONE;
}
static PyObject* py_change_password(PyObject* self, PyObject* args) {
    const char* principal_name;
    const char* new_password;

    if (!PyArg_ParseTuple(args, "ss", &principal_name, &new_password))
        return NULL;

    int ret = change_password(principal_name, new_password);
    if (ret) {
        // Error already set by CHECK_RET
        return NULL;
    }

    Py_RETURN_NONE;
}
// Python wrapper function for list_principals
static PyObject* py_list_principals(PyObject* self, PyObject* args) {

    char **princ_list;
    int count;
    const char* keytab_path;
    printf("Entering py_list_principals\n");

    if (!PyArg_ParseTuple(args, "s", &keytab_path))
            return NULL;


    int ret = list_principals(&princ_list, &count, keytab_path);
        if (ret) {
        printf("123");
        return NULL;
    }

    PyObject *list = PyList_New(count);
    for (int i = 0; i < count; i++) {
        PyList_SetItem(list, i, Py_BuildValue("s", princ_list[i]));
    }

    kadm5_free_name_list(NULL, princ_list, &count);
    return list;
}

// Python wrapper function for add_principal
static PyObject* py_add_principal(PyObject* self, PyObject* args) {
    const char* principal_name;
    const char* password;
    const char* keytab_path;
    long pw_expiration_time;
    long princ_expiration_time;
    int account_disabled;

    if (!PyArg_ParseTuple(args, "ssslli", &principal_name, &password, &keytab_path, &pw_expiration_time, &princ_expiration_time, &account_disabled))
        return NULL;

    int ret = add_principal(principal_name, password, keytab_path, (time_t)pw_expiration_time, (time_t)princ_expiration_time, account_disabled);
    if (ret) {
        // Error already set by CHECK_RET
        return NULL;
    }

    Py_RETURN_NONE;
}
// Method definition object
static PyMethodDef KadminMethods[] = {
    {"get_principal_info", py_get_principal_info, METH_VARARGS, "Get principal info"},
    {"delete_principal", py_delete_principal, METH_VARARGS, "Delete principal"},
    {"list_principals", py_list_principals, METH_VARARGS, "List principals"},
    {"add_principal", py_add_principal, METH_VARARGS, "Add principal"},
    {"change_password", py_change_password, METH_VARARGS, "Change password"}, 
    {"modify_principal", py_modify_principal, METH_VARARGS, "Modify principal"},
    {NULL, NULL, 0, NULL}
};

// Module definition
static struct PyModuleDef kadminmodule = {
    PyModuleDef_HEAD_INIT,
    "kadmin",  // Module name
    NULL,      // Module documentation
    -1,        // Size of per-interpreter state or -1
    KadminMethods
};

// Module initialization function
PyMODINIT_FUNC PyInit_kadmin(void) {
    return PyModule_Create(&kadminmodule);
}
