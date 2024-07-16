#include <Python.h>
#include <krb5.h>
#include <com_err.h>
#include <stdlib.h>
#include <string.h>

/**
 * Change the Kerberos password using the old password.
 *
 * @param context Kerberos context
 * @param principal Kerberos principal
 * @param old_password Old password
 * @param new_password New password
 * @param error_msg Error message buffer
 * @return 0 on success, non-zero error code on failure
 */
int change_password_old(krb5_context context, krb5_principal principal, const char *old_password, const char *new_password, char **error_msg) {

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
        *error_msg = strdup("allocating options failed");
        return ret;
    }

    // Get initial credentials using the old password
    ret = krb5_get_init_creds_password(context, &creds, principal, old_password, NULL, NULL, 0, "kadmin/changepw", opts);
    if (ret) {
        *error_msg = strdup("getting initial credentials failed");
        krb5_get_init_creds_opt_free(context, opts);
        return ret;
    }

    // Construct kpasswd principal
    const char *realm = krb5_principal_get_realm(context, principal);
    ret = krb5_build_principal(context, &kpasswd_principal, strlen(realm), realm, "kadmin", "changepw", NULL);
    if (ret) {
        *error_msg = strdup("constructing kpasswd principal failed");
        krb5_free_cred_contents(context, &creds);
        krb5_get_init_creds_opt_free(context, opts);
        return ret;
    }

    // Change the password
    ret = krb5_change_password(context, &creds, new_password, &result_code, &result_code_string, &result_string);
    if (ret || result_code != 0) {
        if (ret) {
            *error_msg = strdup("changing password failed");
        } else {
            *error_msg = (char *)malloc(result_string.length + 1);
            if (*error_msg) {
                strncpy(*error_msg, result_string.data, result_string.length);
                (*error_msg)[result_string.length] = '\0';
            }
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

/**
 * Change the Kerberos password using a keytab.
 *
 * @param context Kerberos context
 * @param target_principal Target Kerberos principal
 * @param keytab_path Path to the keytab file
 * @param new_password New password
 * @param error_code Error code buffer
 * @param error_message Error message buffer
 */
void change_password_keytab(krb5_context context, krb5_principal target_principal, const char *keytab_path, const char *new_password, krb5_error_code *error_code, char **error_message) {

    krb5_creds creds;
    krb5_get_init_creds_opt *opts;
    krb5_keytab keytab;
    krb5_principal keytab_principal = NULL;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_error_code ret;
    int result_code;
    krb5_data result_code_string = {0}, result_string = {0};

    memset(&creds, 0, sizeof(creds));
    *error_code = 0;
    *error_message = NULL;

    // Initialize options
    ret = krb5_get_init_creds_opt_alloc(context, &opts);
    if (ret) {
        *error_code = ret;
        *error_message = strdup("allocating options");
        return;
    }

    // Resolve the keytab
    ret = krb5_kt_resolve(context, keytab_path, &keytab);
    if (ret) {
        *error_code = ret;
        *error_message = strdup("resolving keytab");
        krb5_get_init_creds_opt_free(context, opts);
        return;
    }

    // Get the principal from the keytab
    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret) {
        *error_code = ret;
        *error_message = strdup("starting keytab entry sequence");
        krb5_kt_close(context, keytab);
        krb5_get_init_creds_opt_free(context, opts);
        return;
    }

    ret = krb5_kt_next_entry(context, keytab, &entry, &cursor);
    if (ret) {
        *error_code = ret;
        *error_message = strdup("getting next keytab entry");
        krb5_kt_end_seq_get(context, keytab, &cursor);
        krb5_kt_close(context, keytab);
        krb5_get_init_creds_opt_free(context, opts);
        return;
    }

    keytab_principal = entry.principal;
    krb5_kt_end_seq_get(context, keytab, &cursor);

    // Get initial credentials using the keytab
    ret = krb5_get_init_creds_keytab(context, &creds, keytab_principal, keytab, 0, "kadmin/changepw", opts);
    if (ret) {
        *error_code = ret;
        *error_message = strdup("getting initial credentials");
        krb5_free_principal(context, keytab_principal);
        krb5_kt_close(context, keytab);
        krb5_get_init_creds_opt_free(context, opts);
        return;
    }

    // Change the password
    ret = krb5_set_password(context, &creds, new_password, target_principal, &result_code, &result_code_string, &result_string);
    if (ret || result_code != 0) {
        if (ret) {
            *error_code = ret;
            *error_message = strdup("changing password");
        } else {
            *error_code = result_code;
            *error_message = (char *)malloc(result_string.length + 1);
            if (*error_message) {
                strncpy(*error_message, result_string.data, result_string.length);
                (*error_message)[result_string.length] = '\0';
            }
        }
        krb5_free_cred_contents(context, &creds);
        krb5_kt_close(context, keytab);
        krb5_get_init_creds_opt_free(context, opts);
        krb5_free_data_contents(context, &result_code_string);
        krb5_free_data_contents(context, &result_string);
        return;
    }

    // Free resources
    krb5_free_cred_contents(context, &creds);
    krb5_kt_close(context, keytab);
    krb5_get_init_creds_opt_free(context, opts);
    krb5_free_data_contents(context, &result_code_string);
    krb5_free_data_contents(context, &result_string);

}

/**
 * Python binding for change_password_old.
 *
 * @param self Self reference for Python C extension
 * @param args Python arguments (principal_name, old_password, new_password)
 * @return None on success, raises RuntimeError on failure
 */
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
    ret = change_password_old(context, principal, old_password, new_password, &error_msg);
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

/**
 * Python binding for change_password_keytab.
 *
 * @param self Self reference for Python C extension
 * @param args Python arguments (target_principal_name, realm, keytab_path, new_password)
 * @return None on success, raises RuntimeError on failure
 */
static PyObject* py_change_password_keytab(PyObject* self, PyObject* args) {
    const char *target_principal_name, *realm, *keytab_path, *new_password;
    krb5_context context;
    krb5_principal target_principal;
    krb5_error_code ret;
    krb5_error_code error_code;
    char *error_message = NULL;

    if (!PyArg_ParseTuple(args, "ssss", &target_principal_name, &realm, &keytab_path, &new_password)) {
        return NULL;
    }

    // Initialize Kerberos context
    ret = krb5_init_context(&context);
    if (ret) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to initialize Kerberos context");
        return NULL;
    }

    // Construct the full principal name with the specified realm
    char full_principal[256];
    snprintf(full_principal, sizeof(full_principal), "%s@%s", target_principal_name, realm);

    // Parse the principal name
    ret = krb5_parse_name(context, full_principal, &target_principal);
    if (ret) {
        krb5_free_context(context);
        PyErr_SetString(PyExc_RuntimeError, "Failed to parse principal name");
        return NULL;
    }

    // Change the password
    change_password_keytab(context, target_principal, keytab_path, new_password, &error_code, &error_message);

    if (error_code) {
        PyErr_Format(PyExc_RuntimeError, "Kerberos error %d: %s", error_code, error_message);
        free(error_message);
        krb5_free_principal(context, target_principal);
        krb5_free_context(context);
        return NULL;
    }

    // Free resources
    krb5_free_principal(context, target_principal);
    krb5_free_context(context);

    Py_RETURN_NONE;
}

// Method definition object
static PyMethodDef KerberosMethods[] = {
    {"change_password_old", py_change_password_old, METH_VARARGS, "Change the Kerberos password using old password"},
    {"change_password_keytab", py_change_password_keytab, METH_VARARGS, "Change the Kerberos password using keytab"},
    {NULL, NULL, 0, NULL}
};

// Module definition
static struct PyModuleDef kerberosservice_module = {
    PyModuleDef_HEAD_INIT,
    "kerberosservice", // Module name
    NULL,              // Module documentation
    -1,                // Size of per-interpreter state or -1
    KerberosMethods
};

// Module initialization function
PyMODINIT_FUNC PyInit_kerberosservice(void) {
    return PyModule_Create(&kerberosservice_module);
}
