#include <Python.h>
#include <krb5.h>
#include <com_err.h>
#include <stdlib.h>
#include <string.h>

int change_password_old(krb5_context context, krb5_principal principal, const char *old_password, const char *new_password, char **error_msg) {
    printf("Debug: Entering change_password function.\n");

    krb5_creds creds;
    krb5_get_init_creds_opt *opts;
    krb5_error_code ret;
    int result_code;
    krb5_data result_code_string = {0}, result_string = {0};
    krb5_principal kpasswd_principal = NULL;

    memset(&creds, 0, sizeof(creds));

    // Initialize options
    ret = krb5_get_init_creds_opt_alloc(context, &opts);
    if (ret) {
        *error_msg = strdup("Allocating options failed");
        return ret;
    }

    // Get initial credentials using the old password
    ret = krb5_get_init_creds_password(context, &creds, principal, old_password, NULL, NULL, 0, "kadmin/changepw", opts);
    if (ret) {
        *error_msg = strdup("Getting initial credentials failed");
        krb5_get_init_creds_opt_free(context, opts);
        return ret;
    }

    // Construct kpasswd principal
    const char *realm = krb5_principal_get_realm(context, principal);
    ret = krb5_build_principal(context, &kpasswd_principal, strlen(realm), realm, "kadmin", "admin", NULL);
    if (ret) {
        *error_msg = strdup("Constructing kpasswd principal failed");
        krb5_free_cred_contents(context, &creds);
        krb5_get_init_creds_opt_free(context, opts);
        return ret;
    }

    // Change the password
    ret = krb5_change_password(context, &creds, new_password, &result_code, &result_code_string, &result_string);
    if (ret || result_code != 0) {
        *error_msg = (char *)malloc(result_string.length + 1);
        if (*error_msg) {
            strncpy(*error_msg, result_string.data, result_string.length);
            (*error_msg)[result_string.length] = '\0';
        }
        krb5_free_cred_contents(context, &creds);
        krb5_get_init_creds_opt_free(context, opts);
        krb5_free_principal(context, kpasswd_principal);
        krb5_free_data_contents(context, &result_code_string);
        krb5_free_data_contents(context, &result_string);
        return ret ? ret : -1; // Use a negative value for non-krb5 errors
    }

    // Free resources
    krb5_free_cred_contents(context, &creds);
    krb5_get_init_creds_opt_free(context, opts);
    krb5_free_principal(context, kpasswd_principal);
    krb5_free_data_contents(context, &result_code_string);
    krb5_free_data_contents(context, &result_string);

    return 0;
}

static PyObject* py_change_password_old(PyObject* self, PyObject* args) {
    const char *principal_name, *old_password, *new_password;
    krb5_context context;
    krb5_principal principal;
    krb5_error_code ret;
    char *error_msg = NULL;

    if (!PyArg_ParseTuple(args, "sss", &principal_name, &old_password, &new_password)) {
        return NULL;
    }

    // Initialize Kerberos context
    ret = krb5_init_context(&context);
    if (ret) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to initialize Kerberos context");
        return NULL;
    }

    // Parse the principal name
    ret = krb5_parse_name(context, principal_name, &principal);
    if (ret) {
        krb5_free_context(context);
        PyErr_SetString(PyExc_RuntimeError, "Failed to parse principal name");
        return NULL;
    }

    // Change the password
    ret = py_change_password_old(context, principal, old_password, new_password, &error_msg);
    if (ret) {
        krb5_free_principal(context, principal);
        krb5_free_context(context);
        if (error_msg) {
            PyErr_SetString(PyExc_RuntimeError, error_msg);
            free(error_msg);
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Password change failed");
        }
        return NULL;
    }

    // Free resources
    krb5_free_principal(context, principal);
    krb5_free_context(context);

    Py_RETURN_NONE;
}

// Method definition object
static PyMethodDef KerberosMethods[] = {
    {"change_password_old", py_change_password, METH_VARARGS, "Change the Kerberos password"},
    {NULL, NULL, 0, NULL}
};

// Module definition
static struct PyModuleDef kerberosservicemodule = {
    PyModuleDef_HEAD_INIT,
    "kerberosservice", // Module name
    NULL,             // Module documentation
    -1,               // Size of per-interpreter state or -1
    KerberosMethods
};

// Module initialization function
PyMODINIT_FUNC PyInit_kerberosservice(void) {
    return PyModule_Create(&kerberosservicemodule);
}
