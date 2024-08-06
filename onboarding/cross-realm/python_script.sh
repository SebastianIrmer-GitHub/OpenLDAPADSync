#!/bin/bash

python3 -m venv env

source env/bin/activate 

pip install setuptools
pip install colorlog
pip install ldap3 
pip install pyyaml

if [ -d "kadmin" ]; then
  echo "kadmin folder already exists."
else
  # Create the kadmin folder
  mkdir kadmin
  echo "kadmin folder created."
fi

sudo kadmin -l ext -k py/admin.keytab admin/admin

if [ -d "kerberosservice" ]; then
  echo "kerberosservice folder already exists."
else
  # Create the kadmin folder
  mkdir kerberosservice
  echo "kerberosservice folder created."
fi

mkdir -p py
cat <<EOF > py/server-config.yaml
ldap:
  server: "ldap://openldap.heimdal.uni-magdeburg.de"
  user: "cn=admin,dc=openldap,dc=heimdal,dc=uni-magdeburg,dc=de"
  password: "Abc1234"
  search_base: "dc=openldap,dc=heimdal,dc=uni-magdeburg,dc=de"
  search_filter: "(objectClass=domainAccount)"
  attributes: ["userAccountControl", "shadowExpire", "uid", "cn", "employeeID"]
  domain: "HEIMDAL.UNI-MAGDEBURG.DE"
  keytab: "admin.keytab"
ad:
  server: "ldap://kerberos.uni-magdeburg.de"
  user: "cn=Administrator,cn=Users,dc=kerberos,dc=uni-magdeburg,dc=de"
  password: "Abc1234"
  search_base: "dc=kerberos,dc=uni-magdeburg,dc=de"
  search_filter: "(objectClass=user)"
  attributes: ["userAccountControl", "accountExpires", "uid", "cn", "employeeID"]
  domain: "KERBEROS.UNI-MAGDEBURG.DE"
  keytab: "svc_passchange.keytab"
EOF

cat <<EOF > py/main.py
from ldap_monitor import LDAPMonitor

def main():
    """
    Main function to initialize and run the LDAPMonitor.

    This function creates an instance of LDAPMonitor with the specified 
    configuration and log files, and then starts the monitor.

    Parameters:
    None

    Returns:
    None
    """
    monitor = LDAPMonitor(config_file='server-config.yaml', log_file='ldap_monitor.log')
    monitor.run()

if __name__ == "__main__":
    
    main()

EOF
cat <<EOF > py/kerberos_principal.py

class Principal:
    """
    A class representing a Kerberos principal with various attributes.

    Attributes:
    user_account_control (int): The user account control settings.
    princ_expiration_time (str): The expiration time of the principal.
    pw_expiration_time (str): The password expiration time.
    username (str): The username of the principal.
    employee_id (str): The employee ID associated with the principal.
    """
    def __init__(self, user_account_control, princ_expiration_time, pw_expiration_time, username, employee_id):
        """
        Initializes a new instance of the Principal class.

        Parameters:
        user_account_control (int): The user account control settings.
        princ_expiration_time (str): The expiration time of the principal.
        pw_expiration_time (str): The password expiration time.
        username (str): The username of the principal.
        employee_id (str): The employee ID associated with the principal.
        """
        self.user_account_control = user_account_control
        self.princ_expiration_time = princ_expiration_time
        self.pw_expiration_time = pw_expiration_time
        self.username = username
        self.employee_id = employee_id

    def __repr__(self):
        """
        Returns a string representation of the Principal instance.

        Returns:
        str: A string representation of the Principal instance.
        """
        return f"Principal(username={self.username}, employee_id={self.employee_id}, princ_expiration_time={self.princ_expiration_time}, pw_expiration_time={self.pw_expiration_time}, user_account_control={self.user_account_control})"

EOF


cat <<EOF > kadmin/setup.py
from setuptools import setup, Extension

module = Extension(
    'kadmin',
    sources=['kadmin_interface_wrapper.c'],
    include_dirs=['/usr/include/heimdal'],
    library_dirs=['/usr/lib/x86_64-linux-gnu/heimdal', '/usr/lib/x86_64-linux-gnu'],
    libraries=['kadm5clnt', 'krb5', 'asn1', 'com_err', 'roken']
)

setup(
    name='kadmin',
    version='1.0',
    description='Python interface to kadmin',
    ext_modules=[module]
)
EOF

cat <<EOF > kerberosservice/setup.py
from setuptools import setup, Extension

module = Extension(
    'kerberosservice',
    sources=['kerberosservice.c'],
    include_dirs=['/usr/include/heimdal'],
    library_dirs=['/usr/lib/x86_64-linux-gnu/heimdal', '/usr/lib/x86_64-linux-gnu'],
    libraries=['krb5', 'com_err']
)

setup(
    name='kerberosservice',
    version='1.0',
    description='Python interface to kerberosserivce',
    ext_modules=[module]
)

EOF

cat <<EOF > kerberosservice/kerberosservice.c
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
        return ret ? ret : -1; 
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
EOF

cat <<EOF > kadmin/kadmin_interface_wrapper.c
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
static PyObject* Kadmin_get_principal(Kadmin* self, PyObject* args) {
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
    {"get_principal", (PyCFunction)Kadmin_get_principal, METH_VARARGS, "Get principal info"},
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


EOF


cat <<EOF > py/enum_change_type.py
from enum import Enum

class ChangeType(Enum):
    """Enum class for representing change types in LDAP entries."""
    ADDED = "Added"
    MODIFIED = "Modified"
    DELETED = "Deleted"
    PWD_LAST_SET = "PwdLastSet"
EOF

cat <<EOF > py/ldap_monitor.py
import logging
from colorlog import ColoredFormatter
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, MODIFY_REPLACE
import time
import yaml
import string
import random
import os
from datetime import datetime, timezone, timedelta
import kadmin
import kerberosservice
import threading
from kerberos_principal import Principal
from enum_change_type import ChangeType

class LDAPMonitor:
    """
    A class to monitor and manage changes in LDAP entries.

    Attributes:
        logger (logging.Logger): Logger for the class.
        ldap_config (dict): Configuration parameters for LDAP.
        ldap_conn (ldap3.Connection): LDAP connection object.
        last_results (list): Last fetched LDAP results.
        check_interval (int): Interval between checks.
        domain (str): Domain name.
        keytab (str): Keytab file.
        kadmin (kadmin.Kadmin): Kadmin object for Kerberos operations.
        ad_config (dict): Configuration parameters for Active Directory.
        ad_ldap_conn (ldap3.Connection): LDAP connection object for Active Directory.
    """

    def __init__(self, config_file='server-config.yaml', log_file='ldap_monitor.log', polling_interval=2):
        """
        Initialize the LDAPMonitor instance.

        Args:
            config_file (str): Path to the LDAP configuration file.
            log_file (str): Path to the log file.
        """
        self.logger = self.setup_logger('LDAPMonitor', log_file)
        self.config = self.load_config(config_file)
        self.ldap_config = self.config['ldap']
        self.ad_config = self.config['ad']
        
        self.ldap_conn = self.connect_ldap(self.ldap_config)
        self.ad_ldap_conn = self.connect_ldap(self.ad_config)
        
        self.last_results = None
        self.check_interval = polling_interval
        self.domain = self.ldap_config["domain"]
        self.keytab = self.ldap_config["keytab"]

        # Initialize the Kadmin object
        self.kadmin = kadmin.Kadmin(self.keytab, self.domain)
        self.ldap_usernames = []
        self.kerberos_principals = []
        

    @staticmethod
    def setup_logger(name, log_file):
        """Configures and returns a colored logger with the given name."""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)

        ch = logging.StreamHandler()
        
        fh = logging.FileHandler(log_file)

        formatter = ColoredFormatter(
            "%(log_color)s%(asctime)s.%(msecs)03d - %(levelname)-8s%(reset)s -  %(blue)s%(message)s",
            datefmt='%Y-%m-%d %H:%M:%S',
            reset=True,
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            },
            secondary_log_colors={},
            style='%'
        )
       
        file_formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d - %(levelname)-8s - %(message)s",
            datefmt='%Y-%m-%d %H:%M:%S',
            style='%'
        )

        ch.setFormatter(formatter)
        fh.setFormatter(file_formatter)
        logger.addHandler(ch)
        logger.addHandler(fh)

        return logger

    @staticmethod
    def load_config(config_file):
        """
        Load the LDAP configuration from a YAML file.

        Args:
            config_file (str): Path to the configuration file.

        Returns:
            dict: A dictionary containing configuration parameters.
        """
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
        return config

    def connect_ldap(self, ldap_config=None):
        """
        Connect to the LDAP server.

        Args:
            ldap_config (dict): LDAP configuration parameters.

        Returns:
            ldap3.Connection: An LDAP connection object.
        """
        if not ldap_config:
            ldap_config = self.ldap_config

        server = Server(ldap_config['server'], get_info=ALL)
        conn = Connection(server, ldap_config['user'], ldap_config['password'], auto_bind=True)
        return conn

    def perform_ldap_search(self):
        """
        Perform an LDAP search based on the configuration.

        Returns:
            list: A list of LDAP entries matching the search criteria.
        """
        attributes = ALL_ATTRIBUTES if "*" in self.ldap_config['attributes'] else self.ldap_config['attributes']
        self.ldap_conn.search(
            self.ldap_config['search_base'],
            self.ldap_config['search_filter'],
            SUBTREE,
            attributes=attributes
        )
        return self.ldap_conn.entries

    def check_for_changes(self):
        """
        Check for changes in the LDAP entries compared to the last results.

        Returns:
            dict: A dictionary containing the current LDAP entries and a dict of changes.
        """
        current_results = self.perform_ldap_search()
        if self.last_results is None:
            return {"current_results": current_results, "changes": {}}

        changes = {}
        
    
        current_dict = {}
        for entry in current_results:
            employee_id = entry.employeeID.value if hasattr(entry.employeeID, 'value') else entry.employeeID
            current_dict[employee_id] = entry

        last_dict = {}
        for entry in self.last_results:
            employee_id = entry.employeeID.value if hasattr(entry.employeeID, 'value') else entry.employeeID
            last_dict[employee_id] = entry

    
        for employee_id, current_entry in current_dict.items():
            last_entry = last_dict.get(employee_id)
            uid = current_entry.uid

            if last_entry is None:
                changes[employee_id] = {
                    "change_type": ChangeType.ADDED,
                    "uid": uid,
                    "employee_id": employee_id
                }
            elif current_entry.entry_attributes_as_dict != last_entry.entry_attributes_as_dict:
                if not self.is_pwd_last_change_only_change(current_entry, last_entry):
                    changes[employee_id] = {
                        "change_type": ChangeType.MODIFIED,
                        "uid": uid,
                        "employee_id": employee_id
                    }
                else:
                    changes[employee_id] = {
                        "change_type": ChangeType.PWD_LAST_SET,
                        "uid": uid,
                        "employee_id": employee_id
                    }

        # Check for deleted entries
        for employee_id, last_entry in last_dict.items():
            if employee_id not in current_dict:
                changes[employee_id] = {
                    "change_type": ChangeType.DELETED,
                    "uid": last_entry.uid,
                    "employee_id": employee_id
                }
    
        return {"current_results": current_results, "changes": changes}

    def add_principal_to_kerberos(self, password, principal):
        """
        Add a principal to Kerberos.

        Args:
            principal (Principal): The principal to add.
        """
        try:
            self.kadmin.add_principal(
                principal.username,
                password,
                principal.pw_expiration_time,
                principal.princ_expiration_time,
                principal.user_account_control
            )
            self.logger.info("Principal %s added to Kerberos.", principal.username)
        except RuntimeError as e:
            self.logger.error("Error adding principal %s: %s", principal.username, e)

    def modify_principal_in_kerberos(self, principal):
        """
        Modify a principal in Kerberos.

        Args:
            principal (Principal): The principal to modify.
        """
        try:
            self.kadmin.modify_principal(
                str(principal.username),
                principal.princ_expiration_time,
                principal.user_account_control
            )
            self.logger.info("Principal %s modified in Kerberos.", principal.username)
        except Exception as e:
            self.logger.error("Error modifying principal %s: %s", principal.username, e)

    @staticmethod
    def extract_username_from_dn(dn):
        """
        Extract the username from the distinguished name (DN).

        Args:
            dn (str): The distinguished name.

        Returns:
            str: The extracted username.
        """
        return dn.split(',')[0].split('=')[1]

    @staticmethod
    def generate_password():
        """
        Generate a random 8-character password including at least one special character.

        Returns:
            str: The generated password.
        """
        letters_and_digits = string.ascii_letters + string.digits
        special_characters = string.punctuation

        password = [
            random.choice(letters_and_digits) for _ in range(7)
        ]

        password.append(random.choice(special_characters))

        random.shuffle(password)

        return ''.join(password)

    @staticmethod
    def save_password_to_file(username, password):
        """
        Save the password to a file named after the username.

        Args:
            username (str): The username.
            password (str): The password.
        """
        os.makedirs('user_passwords', exist_ok=True)
        with open(f'user_passwords/{username}.txt', 'w') as f:
            f.write(password)

    def delete_principal_from_kerberos(self, principal):
        """
        Delete a principal from Kerberos.

        Args:
            principal (str): The principal to be deleted.
        """
        try:
            self.kadmin.delete_principal(principal)
            self.logger.info("Principal %s deleted from Kerberos.", principal)
        except RuntimeError as e:
            self.logger.error("Error deleting principal %s: %s", principal, e)

    @staticmethod
    def get_account_disabled(user_account_control):
        """
        Determine if the account is disabled based on userAccountControl attribute.

        Args:
            user_account_control (int): The userAccountControl attribute from LDAP.

        Returns:
            int: 1 if the account is disabled, 0 otherwise.
        """
        return 1 if user_account_control & 0x2 else 0

    @staticmethod
    def convert_to_generalized_time(timestamp=None):
        """
        Convert the given timestamp to LDAP Generalized Time format (YYYYMMDDHHMMSSZ).

        Args:
            timestamp (float): The timestamp to convert. If None, use the current time.

        Returns:
            str: The time in LDAP Generalized Time format.
        """
        now = datetime.now(timezone.utc) if timestamp is None else datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return now.strftime('%Y%m%d%H%M%SZ')

    def add_pwd_last_change_to_ldap(self, principal):
        """
        Add the pwdLastChange attribute to an LDAP entry by employeeID.

        Args:
            principal (Principal): The principal containing the employeeID.
        """
        try:
            search_filter = f"(employeeID={principal.employee_id})"
            
            search_attributes = ['distinguishedName']

            
            self.ldap_conn.search(self.ldap_config['search_base'], search_filter, SUBTREE, attributes=search_attributes)
            result = self.ldap_conn.entries

            if not result:
                self.logger.error("No LDAP entry found for employeeID %s", principal.employee_id)
                return

            dn = result[0].entry_dn  #

            
            generalized_time = self.convert_to_generalized_time()
            
            self.ldap_conn.modify(
                dn,
                {'pwdLastSet': [(MODIFY_REPLACE, [generalized_time])]}
            )

            if self.ldap_conn.result['result'] == 0:
                self.logger.info("Added pwdLastSet to %s", dn)
            else:
                self.logger.error("Failed to add pwdLastSet to %s: %s", dn, self.ldap_conn.result['description'])

        except Exception as e:
            self.logger.error("Exception while adding pwdLastSet to employeeID %s: %s", principal.employee_id, e)


    @staticmethod
    def is_pwd_last_change_only_change(current, last):
        """
        Check if the only change between current and last is the addition of the pwdLastChange attribute.

        Args:
            current (ldap3.Entry): The current LDAP entry.
            last (ldap3.Entry): The previous LDAP entry.

        Returns:
            bool: True if the only change is pwdLastChange, False otherwise.
        """
        current_attrs = current.entry_attributes_as_dict
        last_attrs = last.entry_attributes_as_dict

        if 'pwdLastSet' in current_attrs and 'pwdLastSet' in last_attrs:
            temp_current_attrs = current_attrs.copy()
            temp_last_attrs = last_attrs.copy()
            temp_current_attrs.pop('pwdLastSet')
            temp_last_attrs.pop('pwdLastSet')
            return temp_current_attrs == temp_last_attrs

        if 'pwdLastSet' in current_attrs and 'pwdLastSet' not in last_attrs:
            temp_current_attrs = current_attrs.copy()
            temp_current_attrs.pop('pwdLastSet')
            return temp_current_attrs == last_attrs

        return False

    @staticmethod
    def ldap_time_to_kerberos_time(shadow_expire):
        """
        Convert shadowExpire (number of days since Unix epoch) to Unix timestamp (Kerberos format).

        Args:
            ldap_timestamp (int): LDAP timestamp in Windows FileTime format.

        Returns:
            int: Unix timestamp in Kerberos format.
        """
        kerberos_timestamp = shadow_expire * 86400

        return kerberos_timestamp
    # ppCGCoxO
    @staticmethod
    def kerberos_time_to_ldap_time(kerberos_timestamp):
        """
        Convert a Unix timestamp (Kerberos format) to LDAP timestamp (Windows FileTime format).

        Args:
            kerberos_timestamp (int): Unix timestamp in Kerberos format.

        Returns:
            int: LDAP timestamp in Windows FileTime format.
        """
        epoch_start = datetime(1601, 1, 1, tzinfo=timezone.utc)  
        kerberos_datetime = datetime.fromtimestamp(kerberos_timestamp, tz=timezone.utc)  
        ldap_time = int((kerberos_datetime - epoch_start).total_seconds() * 10**7)
        return ldap_time
    
    def update_user_account_control_in_ad(self, employee_id, user_account_control):
        """
        Update the userAccountControl attribute for a user in Active Directory.

        Args:
            employee_id (str): The employeeID of the LDAP entry.
            user_account_control (int): The value to set for userAccountControl.
        """
        dn, _ = self.search_user_in_ad_by_employee_id(employee_id)
        if not dn:
            self.logger.error("Failed to find DN for employeeID %s", employee_id)
            return

        try:
            self.ad_ldap_conn.modify(
                dn,
                {'userAccountControl': [(MODIFY_REPLACE, [user_account_control])]}
            )
            if self.ad_ldap_conn.result['result'] == 0:
                pass
            else:
                self.logger.error("Failed to update userAccountControl for %s: %s", dn,
                                  self.ad_ldap_conn.result['description'])
        except Exception as e:
            self.logger.error("Exception while updating userAccountControl for %s: %s", dn, e)

    def list_principals_in_kerberos(self):
        """
        List all principals in Kerberos database.

        Returns:
            list: A list of all principal names.
        """
        try:
            principals = self.kadmin.list_principals()
            return principals
        except RuntimeError as e:
            self.logger.error("Error listing principals: %s", e)
            return []

    def check_principal_exists(self, uid, principals):
        """
        Check if a principal exists in Kerberos based on the UID from OpenLDAP.

        Args:
            uid (str): The UID to check.
            principals (list): List of Principals in Kerberos Database.
        Returns:
            bool: True if the principal exists, False otherwise.
        """
        principal = f"{uid}@{self.domain}"

        if principal in principals:
            return True
        else:
            self.logger.info("Principal %s does not exist in Kerberos.", principal)
            return False

    def search_user_in_ad_by_employee_id(self, employee_id):
        """
        Search for a user in AD using their employeeID and return their distinguished name (DN).

        Args:
            employee_id (str): The employeeID of the user.

        Returns:
            str: The distinguished name of the user, or None if not found.
        """
        self.ad_ldap_conn.search(
            search_base=self.ad_config['search_base'],
            search_filter=f"(employeeID={employee_id})",
            search_scope=SUBTREE,
            attributes=['distinguishedName', 'sAMAccountName']
        )
        if self.ad_ldap_conn.entries:  
            dn = self.ad_ldap_conn.entries[0].distinguishedName.value
            sam_account_name = self.ad_ldap_conn.entries[0].sAMAccountName.value
            return dn, sam_account_name
        return None, None

    def object_exists_in_ad_by_employee_id(self, employee_id):
        """
        Check if an object exists in Active Directory using employeeID.

        Args:
            employee_id (str): The employeeID of the object.

        Returns:
            bool: True if the object exists, False otherwise.
        """
        self.ad_ldap_conn.search(
            search_base=self.ad_config['search_base'],
            search_filter=f"(employeeID={employee_id})",
            search_scope=SUBTREE,
            attributes=['distinguishedName']
        )
        return bool(self.ad_ldap_conn.entries)

    def run(self):
        """
        Main function to load configuration, connect to LDAP, and monitor for changes.
        """
        self.logger.info("Running LDAP-Kerberos Sync...")
        try:
            self.initialize_monitoring()
            self.clean_up_kerberos()
            self.sync_ldap_to_kerberos()
            self.monitor_changes()
        except KeyboardInterrupt:
            self.logger.info("Stopping LDAP monitoring...")
        finally:
            self.ldap_conn.unbind()

    def initialize_monitoring(self):
        """
        Initialize the monitoring by performing an initial LDAP search and setting up usernames.
        """
        initial_results = self.perform_ldap_search()
        self.ldap_usernames = {str(entry.uid) for entry in initial_results}
        self.kerberos_principals = self.list_principals_in_kerberos()

    def clean_up_kerberos(self):
        """
        Clean up Kerberos principals that are not present in LDAP.
        """
        for principal in self.kerberos_principals:
            if self.is_special_principal(principal):
                continue
                
            username = principal.split('@')[0]

            if username not in self.ldap_usernames:
                self.logger.info("Principal %s in Kerberos is not present in LDAP. Deleting...", principal)
                self.delete_principal_from_kerberos(principal)

    def is_special_principal(self, principal):
        """
        Check if the principal is a special one that should be skipped.
        """
        return "/" in principal or "default" in principal or "admin" in principal or "bind" in principal

    def sync_ldap_to_kerberos(self):
        """
        Sync LDAP users to Kerberos, adding any missing principals.
        """
        initial_results = self.perform_ldap_search()
        for entry in initial_results:
            username = str(entry.uid)
            if not self.check_principal_exists(username, self.kerberos_principals):
                user_account_control = self.get_user_account_control(entry)
                princ_expiration_time = self.get_principal_expiration_time(entry)
                pw_expiration_time = int(time.time())
                
                principal = Principal(
                    user_account_control,
                    princ_expiration_time,
                    pw_expiration_time,
                    username,
                    entry.employeeID.value
                )
                threading.Thread(target=self.handle_new_ldap_user, args=(principal,)).start()
                
    def handle_new_ldap_user(self, principal):
        """
        Handle the case where a new LDAP user needs to be added to Kerberos.
        """
        
        password = "Abc1234"  
       
        self.add_principal_to_kerberos(password, principal)
        self.save_password_to_file(principal.username, password)
        self.add_pwd_last_change_to_ldap(principal)
        
        if not self.ad_config['keytab']:
            return

        self.update_ad_user(principal, password)

    def get_user_account_control(self, entry):
        """
        Get the user account control value from the LDAP entry.
        """
        user_account_control = 1
        if "userAccountControl" in entry:
            try:
                if entry.userAccountControl.value:
                    user_account_control = self.get_account_disabled(entry.userAccountControl.value)
            except Exception as e:
                self.logger.error("userAccountControl couldn't be determined: %s", e)
        return user_account_control
    
    def get_principal_expiration_time(self, entry):
        """
        Get the principal expiration time from the LDAP entry.
        """
        princ_expiration_time = int(time.time())
        if "shadowExpire" in entry:
            try:
                if entry.shadowExpire.value:
                    princ_expiration_time = self.ldap_time_to_kerberos_time(entry.shadowExpire.value)
            except Exception as e:
                self.logger.error("Principal expiration time couldn't be determined: %s", e)
        return princ_expiration_time

    def update_account_expires_in_ad(self, employee_id, kerberos_timestamp):
        """
        Update the shadowExpire attribute in Active Directory.

        Args:
            employee_id (str): The employeeID of the LDAP entry.
            kerberos_timestamp (int): The Unix timestamp in Kerberos format.
        """
        dn, _ = self.search_user_in_ad_by_employee_id(employee_id)
        if not dn:
            self.logger.error("Failed to find DN for employeeID %s", employee_id)
            return

        ldap_timestamp = self.kerberos_time_to_ldap_time(kerberos_timestamp)
        try:
            self.ad_ldap_conn.modify(
                dn,
                {'shadowExpire': [(MODIFY_REPLACE, [ldap_timestamp])]}
            )
            if self.ad_ldap_conn.result['result'] == 0:
                pass
            else:
                self.logger.error("Failed to update shadowExpire for %s: %s", dn, self.ad_ldap_conn.result['description'])
        except Exception as e:
            self.logger.error("Exception while updating shadowExpire for %s: %s", dn, e)

    def update_ad_user(self, principal, password):
        """
        Update the AD user with the new password and account control settings.
        """
        
        if not os.path.exists(self.ad_config['keytab']):
            self.logger.info("Keytab file for AD-Sync does not exist, not syncing...")
            return
        
        try:
            _, ad_sam_account_name = self.search_user_in_ad_by_employee_id(principal.employee_id)
        except Exception as e:
            self.logger.error("Couldn't search user in AD: %s", e)
            return

        retries = 5
        for attempt in range(retries):
            
            if ad_sam_account_name:
                try:
                    kerberosservice.change_password_keytab(ad_sam_account_name, self.ad_config['domain'], self.ad_config['keytab'], password)
                except Exception as e:
                    self.logger.error("Couldn't change password of AD User: %s", e)
                    continue
                
                ## This is performed by the LSC Script, not necessary here 
                # self.update_user_account_control_in_ad(principal.employee_id, 512 if principal.user_account_control == 0 else 514)
                # self.update_account_expires_in_ad(principal.employee_id, principal.princ_expiration_time)
                self.logger.info("User with employeeID %s updated in AD {sAMAccountName: %s}", principal.employee_id, ad_sam_account_name)
                break 
            else:
                self.logger.info("User not found in AD, retrying in 2 miuntes... (Attempt %d/%d)", attempt + 1, retries)
                time.sleep(20)
                _, ad_sam_account_name = self.search_user_in_ad_by_employee_id(principal.employee_id)

    def monitor_changes(self):
        """
        Monitor LDAP for changes and handle them accordingly.
        """
        while True:
            result = self.check_for_changes()
            current_results = result["current_results"]
            changes = result["changes"]
            self.handle_changes(changes, current_results)
            self.last_results = current_results
            time.sleep(self.check_interval)

    def handle_changes(self, changes, current_results):
        """
        Handle the changes detected in the LDAP entries.
        """
        for employee_id, change in changes.items():
            change_type = change["change_type"]
            uid = str(change["uid"])
            self.logger.info("%s: EmployeeID %s (UID: %s)", change_type.value, employee_id, uid)

            if change_type == ChangeType.DELETED:
                principal = f"{uid}@{self.domain}"
                self.delete_principal_from_kerberos(principal)
            elif change_type == ChangeType.PWD_LAST_SET:
                continue
            else:
                threading.Thread(target=self.handle_non_deleted_changes, args=(change_type, employee_id, current_results)).start()

    def handle_non_deleted_changes(self, change_type, employee_id, current_results):
        """
        Handle changes that are not deletions.
        """
        entry = next((x for x in current_results if (x.employeeID.value if hasattr(x.employeeID, 'value') else x.employeeID) == employee_id), None)
        username = entry.uid.value
        
        self.ldap_usernames = {str(entry.uid) for entry in current_results}
        self.kerberos_principals = self.list_principals_in_kerberos()
        user_account_control = self.get_user_account_control(entry)
        princ_expiration_time = self.get_principal_expiration_time(entry)
        pw_expiration_time = int(time.time())
        
        principal = Principal(
            user_account_control,
            princ_expiration_time,
            pw_expiration_time,
            username,
            entry.employeeID.value
        )
                
        if change_type == ChangeType.ADDED:
            self.handle_new_ldap_user(principal)
        elif change_type == ChangeType.MODIFIED:
            if not self.check_principal_exists(username, self.kerberos_principals):
                self.handle_new_ldap_user(principal)
            else:
                self.modify_principal_in_kerberos(principal)
                
        # cleaning remaining entries 
        self.clean_up_kerberos()
            
if __name__ == "__main__":
    monitor = LDAPMonitor()
    monitor.run()

EOF

python3 kadmin/setup.py build
python3 kerberosservice/setup.py build

pip install kadmin/
pip install kerberosservice/