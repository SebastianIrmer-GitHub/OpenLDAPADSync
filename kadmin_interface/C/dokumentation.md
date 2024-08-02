# Kerberos Administration Python Module
This document provides the documentation for the Kerberos administration Python module, which provides a Kadmin class for managing Kerberos principals.

Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Kadmin Structure](#kadmin-structure)
- [Macro Definition](#macro-definition)
- [Functions](#functions)
  - [init_context](#init_context)
  - [Kadmin Methods](#kadmin-methods)
    - [Kadmin_get_principal_info](#kadmin_get_principal_info)
    - [Kadmin_list_principals](#kadmin_list_principals)
    - [Kadmin_add_principal](#kadmin_add_principal)
    - [Kadmin_modify_principal](#kadmin_modify_principal)
    - [Kadmin_delete_principal](#kadmin_delete_principal)
    - [Kadmin_change_password](#kadmin_change_password)
  - [Helper Functions](#helper-functions)
    - [free_princ_list](#free_princ_list)
- [Kadmin Object Initialization](#kadmin-object-initialization)
- [Module Definition](#module-definition)
- [Module Initialization](#module-initialization)
- [Usage Examples](#usage-examples)

## Introduction



This module provides a `Kadmin` class that interacts with Kerberos to perform administrative tasks such as adding, modifying, and deleting principals, as well as changing passwords.


## Installation

## Kadmin Structure

Python Onboarding Skript ausführen
/onboarding/cross-realm/python_script.sh

in die Ordner kadmin und kerberosservice die nötigen Dateien
kadmin:
    - setup.py
    - kadmin_interface_wrapper.c
kerberosservice:
    - setup.py
    - kerberosservice.c
installieren.

source /<env>/bin/activate

Dahin navigieren, wo gespeichert ist:

    1. pip setup.py build
    2. pip install .
    3. Danach kann main.py benutzt werden
    4. Einrichten der Konfigurationsdateien (ad-server.yaml, server-config.yaml)
    5. python3 main.py

```c
typedef struct {
    PyObject_HEAD
    krb5_context context;
    void *server_handle;
    char *client_name;
} Kadmin;
```
## Macro Definition
```c
#define CHECK_RET(ret, context, msg) \
    if (ret) { \
        const char *err_msg = krb5_get_error_message(context, ret); \
        PyErr_Format(PyExc_RuntimeError, "%s: %s", msg, strdup(err_msg)); \
        krb5_free_error_message(context, err_msg); \
        goto cleanup; \
    }
```

## Functions

### init_context
```c
krb5_error_code init_context(Kadmin *self, const char *keytab_path, const char *realm, char **error_msg);
```

**Parameters:**
- `self`: Pointer to the Kadmin object.
- `keytab_path`: Path to the keytab file.
- `realm`: Kerberos realm.
- `error_msg`: Pointer to store the error message in case of failure.


**Returns:**

Kerberos error code (0 on success).

## Kadmin Methods

### Kadmin_get_principal_info
Gets information about a Kerberos principal.
```c
static PyObject* Kadmin_get_principal_info(Kadmin* self, PyObject* args);
```
**Parameters:**
- `self`: Pointer to the Kadmin object.
- `args`: Tuple containing the principal name.

**Returns:**

Python dictionary with principal information.

### Kadmin_list_principals
Lists all Kerberos principals.

**Parameters:**
- `self`: Pointer to the Kadmin object.
- `args`: Arguments (not used).
```c
static PyObject* Kadmin_list_principals(Kadmin* self, PyObject* args);
```
**Returns:**

Python list of all principal names.


### Kadmin_add_principal

Adds a new Kerberos principal.
**Parameters:**
- `self`: Pointer to the Kadmin object.
- `args`: Tuple containing the principal name, password, password expiration time, principal expiration time, and account disabled flag.

**Returns:**

None on success, NULL on failure.

### Kadmin_modify_principal

Modifies the attributes of a Kerberos principal.

```c
static PyObject* Kadmin_modify_principal(Kadmin* self, PyObject* args);
```

**Parameters:**
- `self`: Pointer to the Kadmin object.
- `args`: Tuple containing the principal name, principal expiration time, and account disabled flag.

### Kadmin_delete_principal

Deletes a Kerberos principal.

```c
static PyObject* Kadmin_delete_principal(Kadmin* self, PyObject* args);
```

**Parameters:**
- `self`: Pointer to the Kadmin object.
- `args`: Tuple containing the principal name.


**Returns:**

None on success, NULL on failure.

### Kadmin_change_password
Changes the password of a Kerberos principal.
```c
static PyObject* Kadmin_change_password(Kadmin* self, PyObject* args);
```

**Parameters:**
- `self`: Pointer to the Kadmin object.
- `args`: Tuple containing the principal name and new password.


**Returns:**

None on success, NULL on failure.

## Helper Functions
### free_princ_list

Frees the list of principals.

```c
void free_princ_list(char **princ_list, int count);
```

**Parameters:**
- `self`: Pointer to the Kadmin object.
- `count`: Number of principals in the list.

## Kadmin Object Initialization
### Kadmin_init

Initializes the Kadmin object.

```c
static int Kadmin_init(Kadmin *self, PyObject *args, PyObject *kwds);
```

**Parameters:**
- `self`: Pointer to the Kadmin object.
- `args`: Tuple containing the keytab path and realm.
- `kwds`: Keywords (not used).

**Returns:**

0 on success, -1 on failure.

### Kadmin_dealloc
Deallocates the Kadmin object and frees its resources.
```c
static void Kadmin_dealloc(Kadmin* self);
```

## Module Definition

### Kadmin_methods
List of methods available in the Kadmin object.
```c
static PyMethodDef Kadmin_methods[] = {
    {"get_principal_info", (PyCFunction)Kadmin_get_principal_info, METH_VARARGS, "Get principal info"},
    {"list_principals", (PyCFunction)Kadmin_list_principals, METH_VARARGS, "List principals"},
    {"add_principal", (PyCFunction)Kadmin_add_principal, METH_VARARGS, "Add principal"},
    {"modify_principal", (PyCFunction)Kadmin_modify_principal, METH_VARARGS, "Modify principal"},
    {"delete_principal", (PyCFunction)Kadmin_delete_principal, METH_VARARGS, "Delete principal"},
    {"change_password", (PyCFunction)Kadmin_change_password, METH_VARARGS, "Change password"},
    {NULL}  /* Sentinel */
};
```
### KadminType
Definition of the Kadmin type.

```c
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
```

## Module Initialization

### PyInit_kadmin
Module initialization function.
```c
PyMODINIT_FUNC PyInit_kadmin(void);
```

**Returns:**
Module object.

```c

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
```

## Usage Examples
Examples on how to use each method. 
```c

import kadmin

# Initialize the Kadmin object
keytab_path = "/path/to/keytab"
realm = "YOUR.REALM"
admin = kadmin.Kadmin(keytab_path, realm)

# Example 1: Get Principal Information
def get_principal_info(principal_name):
    try:
        info = admin.get_principal_info(principal_name)
        print(f"Principal: {info['principal_name']}")
        print(f"Principal Expire Time: {info['principal_expire_time']}")
        print(f"Password Expiration: {info['pw_expiration']}")
        print(f"Last Password Change: {info['last_pwd_change']}")
        print(f"Max Life: {info['max_life']}")
        print(f"Max Renewable Life: {info['max_renewable_life']}")
    except RuntimeError as e:
        print(f"Error: {e}")

# Example 2: List All Principals
def list_principals():
    try:
        principals = admin.list_principals()
        for principal in principals:
            print(principal)
    except RuntimeError as e:
        print(f"Error: {e}")

# Example 3: Add a New Principal
def add_principal(principal_name, password, pw_expiration_time, princ_expiration_time, account_disabled):
    try:
        admin.add_principal(principal_name, password, pw_expiration_time, princ_expiration_time, account_disabled)
        print(f"Principal {principal_name} added successfully.")
    except RuntimeError as e:
        print(f"Error: {e}")

# Example 4: Modify Principal Attributes
def modify_principal(principal_name, princ_expiration_time, account_disabled):
    try:
        admin.modify_principal(principal_name, princ_expiration_time, account_disabled)
        print(f"Principal {principal_name} modified successfully.")
    except RuntimeError as e:
        print(f"Error: {e}")

# Example 5: Delete a Principal
def delete_principal(principal_name):
    try:
        admin.delete_principal(principal_name)
        print(f"Principal {principal_name} deleted successfully.")
    except RuntimeError as e:
        print(f"Error: {e}")

# Example 6: Change Principal Password
def change_password(principal_name, new_password):
    try:
        admin.change_password(principal_name, new_password)
        print(f"Password for principal {principal_name} changed successfully.")
    except RuntimeError as e:
        print(f"Error: {e}")

# Usage examples:
get_principal_info("testuser@YOUR.REALM")
list_principals()
add_principal("newuser@YOUR.REALM", "password123", 0, 0, False)
modify_principal("newuser@YOUR.REALM", 0, False)
delete_principal("newuser@YOUR.REALM")
change_password("testuser@YOUR.REALM", "newpassword123")

```


This documentation provides an overview of the functions and structures used in the Kerberos administration Python module. For more detailed information, refer to the source code comments and Kerberos documentation.

