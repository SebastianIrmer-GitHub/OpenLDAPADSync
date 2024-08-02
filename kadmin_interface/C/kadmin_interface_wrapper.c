#include <Python.h>
#include <krb5.h>
#include <kadm5/admin.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * Struct representing the Kadmin object.
 */
typedef struct {
    PyObject_HEAD
    krb5_context context;
    void *server_handle;
    char *client_name;
} Kadmin;

/**
 * Macro to check the return value of Kerberos functions.
 * If an error occurs, it sets a Python exception with the error message and goes to the cleanup label.
 */
#define CHECK_RET(ret, context, msg) \
    if (ret) { \
        const char *err_msg = krb5_get_error_message(context, ret); \
        PyErr_Format(PyExc_RuntimeError, "%s: %s", msg, strdup(err_msg)); \
        krb5_free_error_message(context, err_msg); \
        goto cleanup; \
    }

/**
 * Initialize the Kerberos context and admin service handle.
 * @param self Pointer to the Kadmin object.
 * @param keytab_path Path to the keytab file.
 * @param realm Kerberos realm.
 * @param error_msg Pointer to store the error message in case of failure.
 * @return Kerberos error code (0 on success).
 */
krb5_error_code init_context(Kadmin *self, const char *keytab_path, const char *realm, char **error_msg) {
    krb5_error_code ret;
    krb5_principal client_principal = NULL;
    kadm5_config_params params;
    krb5_keytab keytab = NULL;
    krb5_keytab_entry entry;
    krb5_kt_cursor cursor;
    const char *err_msg;
    const char *princ_realm;

    memset(&params, 0, sizeof(params));
    params.mask = KADM5_CONFIG_REALM;
    params.realm = realm;

    ret = krb5_init_context(&self->context);
    if (ret) {
        err_msg = krb5_get_error_message(self->context, ret);
        *error_msg = strdup(err_msg);
        krb5_free_error_message(self->context, err_msg);
        goto cleanup;
    }

    ret = krb5_kt_resolve(self->context, keytab_path, &keytab);
    if (ret) {
        err_msg = krb5_get_error_message(self->context, ret);
        *error_msg = strdup(err_msg);
        krb5_free_error_message(self->context, err_msg);
        goto cleanup;
    }

    ret = krb5_kt_start_seq_get(self->context, keytab, &cursor);
    if (ret) {
        err_msg = krb5_get_error_message(self->context, ret);
        *error_msg = strdup(err_msg);
        krb5_free_error_message(self->context, err_msg);
        goto cleanup;
    }

    // Get the first principal from the keytab
    ret = krb5_kt_next_entry(self->context, keytab, &entry, &cursor);
    if (ret) {
        if (ret == KRB5_KT_NOTFOUND) {
            *error_msg = strdup("Key table entry not found. No entry exists for the service principal in the keytab file.");
        } else {
            err_msg = krb5_get_error_message(self->context, ret);
            *error_msg = strdup(err_msg);
            krb5_free_error_message(self->context, err_msg);
        }
        goto cleanup;
    }

    client_principal = entry.principal;
    ret = krb5_unparse_name(self->context, client_principal, &self->client_name);
    if (ret) {
        err_msg = krb5_get_error_message(self->context, ret);
        *error_msg = strdup(err_msg);
        krb5_free_error_message(self->context, err_msg);
        goto cleanup;
    }

    princ_realm = krb5_principal_get_realm(self->context, client_principal);
    if (strcmp(princ_realm, realm) != 0) {
        *error_msg = strdup("Realm in client_name does not match specified realm");
        ret = 2;
        goto cleanup;
    }

    // Finish keytab iteration
    krb5_kt_end_seq_get(self->context, keytab, &cursor);
    krb5_kt_free_entry(self->context, &entry);

    ret = kadm5_init_with_skey(self->client_name, keytab_path, "kadmin/admin", &params, KADM5_STRUCT_VERSION, KADM5_API_VERSION_2, &self->server_handle);
    if (ret) {
        err_msg = krb5_get_error_message(self->context, ret);
        *error_msg = strdup(err_msg);
        krb5_free_error_message(self->context, err_msg);
        goto cleanup;
    }

    krb5_kt_close(self->context, keytab);
    keytab = NULL;

    return 0;

cleanup:
    if (keytab) {
        krb5_kt_close(self->context, keytab);
    }
    if (client_principal) {
        krb5_free_principal(self->context, client_principal);
    }
    return ret;
}


/**
 * Get information about a Kerberos principal.
 * @param self Pointer to the Kadmin object.
 * @param args Tuple containing the principal name.
 * @return Python dictionary with principal information.
 */
static PyObject* Kadmin_get_principal_info(Kadmin* self, PyObject* args) {
    const char* principal_name;
    kadm5_principal_ent_rec princ;
    krb5_principal krb_principal = NULL;
    if (!PyArg_ParseTuple(args, "s", &principal_name))
        return NULL;
    krb5_error_code ret = krb5_parse_name(self->context, principal_name, &krb_principal);
    CHECK_RET(ret, self->context, "Error parsing principal name");
    ret = kadm5_get_principal(self->server_handle, krb_principal, &princ, KADM5_PRINCIPAL_NORMAL_MASK);
    CHECK_RET(ret, self->context, "Error getting principal");
    
    PyObject* result = Py_BuildValue(
        "{s:s, s:l, s:l, s:l, s:l, s:l}",
        "principal_name", principal_name,
        "principal_expire_time", princ.princ_expire_time,
        "pw_expiration", princ.pw_expiration,
        "last_pwd_change", princ.last_pwd_change,
        "max_life", princ.max_life,
        "max_renewable_life", princ.max_renewable_life
    );

    kadm5_free_principal_ent(self->server_handle, &princ);
    krb5_free_principal(self->context, krb_principal);

    return result;

cleanup:
    if (krb_principal) krb5_free_principal(self->context, krb_principal);
    return NULL;
}

/**
 * List all Kerberos principals.
 * @param self Pointer to the Kadmin object.
 * @param args Arguments (not used).
 * @return Python list of principal names.
 */
static PyObject* Kadmin_list_principals(Kadmin* self, PyObject* args) {
    char **princ_list = NULL;
    int count;
    krb5_error_code ret;
    ret = kadm5_get_principals(self->server_handle, "*", &princ_list, &count);
    if (ret) {
        CHECK_RET(ret, self->context, "Error listing principals");
        return NULL;
    }
    PyObject *list = PyList_New(count);
    if (list == NULL) {
        free_princ_list(princ_list, count);
        return PyErr_NoMemory();
    }

    for (int i = 0; i < count; i++) {
        PyObject *str = Py_BuildValue("s", princ_list[i]);
        if (str == NULL) {
            free_princ_list(princ_list, count);
            Py_DECREF(list);
            return PyErr_NoMemory();
        }
        PyList_SetItem(list, i, str);  // Note: PyList_SetItem steals a reference to str
    }

    free_princ_list(princ_list, count);

    return list;

cleanup:
    if (princ_list != NULL) {
        free_princ_list(princ_list, count);
    }
    return NULL;
}

/**
 * Free the list of principals.
 * @param princ_list List of principal names.
 * @param count Number of principals in the list.
 */
void free_princ_list(char **princ_list, int count) {
    if (princ_list) {
        for (int i = 0; i < count; i++) {
            free(princ_list[i]);
        }
        free(princ_list);
    }
}

/**
 * Add a new Kerberos principal.
 * @param self Pointer to the Kadmin object.
 * @param args Tuple containing the principal name, password, password expiration time, principal expiration time, and account disabled flag.
 * @return None on success, NULL on failure.
 */
static PyObject* Kadmin_add_principal(Kadmin* self, PyObject* args) {
    const char* principal_name;
    const char* password;
    long pw_expiration_time;
    long princ_expiration_time;
    int account_disabled;
    krb5_principal krb_principal = NULL;
    kadm5_principal_ent_rec princ;

    if (!PyArg_ParseTuple(args, "sslli", &principal_name, &password, &pw_expiration_time, &princ_expiration_time, &account_disabled))
        return NULL;

    krb5_error_code ret = krb5_parse_name(self->context, principal_name, &krb_principal);
    CHECK_RET(ret, self->context, "Error parsing principal name");

    memset(&princ, 0, sizeof(princ));
    princ.principal = krb_principal;
    princ.max_life = 0;
    princ.max_renewable_life = 0;
    princ.pw_expiration = pw_expiration_time; 
    if (princ_expiration_time > 0) {
        princ.princ_expire_time = princ_expiration_time;
    }
    if (account_disabled) {
        princ.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
    } else {
        princ.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
    }

    ret = kadm5_create_principal(self->server_handle, &princ, KADM5_PRINCIPAL | KADM5_PW_EXPIRATION | KADM5_PRINC_EXPIRE_TIME | KADM5_ATTRIBUTES, password);
    CHECK_RET(ret, self->context, "Error creating principal");

    krb5_free_principal(self->context, krb_principal);

    Py_RETURN_NONE;

cleanup:
    if (krb_principal) krb5_free_principal(self->context, krb_principal);
    return NULL;
}

/**
 * Modify the attributes of a Kerberos principal.
 * @param self Pointer to the Kadmin object.
 * @param args Tuple containing the principal name, principal expiration time, and account disabled flag.
 * @return None on success, NULL on failure.
 */
static PyObject* Kadmin_modify_principal(Kadmin* self, PyObject* args) {
    const char* principal_name;
    long princ_expiration_time;
    int account_disabled;
    krb5_principal krb_principal = NULL;
    kadm5_principal_ent_rec princ;

    if (!PyArg_ParseTuple(args, "sli", &principal_name, &princ_expiration_time, &account_disabled))
        return NULL;

    krb5_error_code ret = krb5_parse_name(self->context, principal_name, &krb_principal);
    CHECK_RET(ret, self->context, "Error parsing principal name");

    memset(&princ, 0, sizeof(princ));
    princ.principal = krb_principal;

    if (princ_expiration_time > 0) {
        princ.princ_expire_time = princ_expiration_time;
    }
    if (account_disabled) {
        princ.attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
    } else {
        princ.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
    }

    ret = kadm5_modify_principal(self->server_handle, &princ, KADM5_PRINC_EXPIRE_TIME | KADM5_ATTRIBUTES);
    CHECK_RET(ret, self->context, "Error modifying principal");

    krb5_free_principal(self->context, krb_principal);

    Py_RETURN_NONE;

cleanup:
    if (krb_principal) krb5_free_principal(self->context, krb_principal);
    return NULL;
}

/**
 * Delete a Kerberos principal.
 * @param self Pointer to the Kadmin object.
 * @param args Tuple containing the principal name.
 * @return None on success, NULL on failure.
 */
static PyObject* Kadmin_delete_principal(Kadmin* self, PyObject* args) {
    const char* principal_name;
    krb5_principal krb_principal = NULL;

    if (!PyArg_ParseTuple(args, "s", &principal_name))
        return NULL;

    krb5_error_code ret = krb5_parse_name(self->context, principal_name, &krb_principal);
    CHECK_RET(ret, self->context, "Error parsing principal name");

    ret = kadm5_delete_principal(self->server_handle, krb_principal);
    CHECK_RET(ret, self->context, "Error deleting principal");

    krb5_free_principal(self->context, krb_principal);

    Py_RETURN_NONE;

cleanup:
    if (krb_principal) krb5_free_principal(self->context, krb_principal);
    return NULL;
}

/**
 * Change the password of a Kerberos principal.
 * @param self Pointer to the Kadmin object.
 * @param args Tuple containing the principal name and new password.
 * @return None on success, NULL on failure.
 */
static PyObject* Kadmin_change_password(Kadmin* self, PyObject* args) {
    const char* principal_name;
    const char* new_password;
    krb5_principal krb_principal = NULL;

    if (!PyArg_ParseTuple(args, "ss", &principal_name, &new_password))
        return NULL;

    krb5_error_code ret = krb5_parse_name(self->context, principal_name, &krb_principal);
    CHECK_RET(ret, self->context, "Error parsing principal name");

    ret = kadm5_chpass_principal(self->server_handle, krb_principal, new_password);
    CHECK_RET(ret, self->context, "Error changing password");

    krb5_free_principal(self->context, krb_principal);

    Py_RETURN_NONE;

cleanup:
    if (krb_principal) krb5_free_principal(self->context, krb_principal);
    return NULL;
}

/**
 * Initialize the Kadmin object.
 * @param self Pointer to the Kadmin object.
 * @param args Tuple containing the keytab path and realm.
 * @param kwds Keywords (not used).
 * @return 0 on success, -1 on failure.
 */
static int Kadmin_init(Kadmin *self, PyObject *args, PyObject *kwds) {
    self->context = NULL;
    self->server_handle = NULL;
    self->client_name = NULL;

    const char* keytab_path;
    const char* realm;
    char *error_msg = NULL;
    if (!PyArg_ParseTuple(args, "ss", &keytab_path, &realm)) {
        PyErr_SetString(PyExc_ValueError, "Invalid arguments, expected two strings.");
        return -1;
    }
    krb5_error_code ret = init_context(self, keytab_path, realm, &error_msg);
    if (ret) {
        PyErr_Format(PyExc_RuntimeError, "Kerberos error %d: %s", ret, error_msg ? error_msg : "unknown error");
        
        if (error_msg) {
            free(error_msg);
            error_msg = NULL;
        }
        return -1;
    }

    return 0;
}


/**
 * Deallocate the Kadmin object and free its resources.
 * @param self Pointer to the Kadmin object.
 */
static void Kadmin_dealloc(Kadmin* self) {
    if (self->client_name) {
        free(self->client_name);
        self->client_name = NULL;
    }
    if (self->server_handle) {
        kadm5_destroy(self->server_handle);
        self->server_handle = NULL;
    }
    if (self->context) {
        krb5_free_context(self->context);
        self->context = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}

/**
 * List of methods available in the Kadmin object.
 */
static PyMethodDef Kadmin_methods[] = {
    {"get_principal_info", (PyCFunction)Kadmin_get_principal_info, METH_VARARGS, "Get principal info"},
    {"list_principals", (PyCFunction)Kadmin_list_principals, METH_VARARGS, "List principals"},
    {"add_principal", (PyCFunction)Kadmin_add_principal, METH_VARARGS, "Add principal"},
    {"modify_principal", (PyCFunction)Kadmin_modify_principal, METH_VARARGS, "Modify principal"},
    {"delete_principal", (PyCFunction)Kadmin_delete_principal, METH_VARARGS, "Delete principal"},
    {"change_password", (PyCFunction)Kadmin_change_password, METH_VARARGS, "Change password"},
    {NULL}  /* Sentinel */
};

/**
 * Definition of the Kadmin type.
 */
static PyTypeObject KadminType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "kadmin.Kadmin",             /* tp_name */
    sizeof(Kadmin),             /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)Kadmin_dealloc, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,        /* tp_flags */
    "Kadmin objects",           /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    Kadmin_methods,             /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)Kadmin_init,      /* tp_init */
    0,                         /* tp_alloc */
    PyType_GenericNew,         /* tp_new */
};

/**
 * Module definition.
 */
static PyModuleDef kadminmodule = {
    PyModuleDef_HEAD_INIT,
    "kadmin",
    "Kerberos admin module",
    -1,
    NULL, NULL, NULL, NULL, NULL
};

/**
 * Module initialization function.
 * @return Module object.
 */
PyMODINIT_FUNC PyInit_kadmin(void) {
    PyObject* m;

    if (PyType_Ready(&KadminType) < 0)
        return NULL;

    m = PyModule_Create(&kadminmodule);
    if (m == NULL)
        return NULL;

    Py_INCREF(&KadminType);
    PyModule_AddObject(m, "Kadmin", (PyObject *)&KadminType);
    return m;
}
