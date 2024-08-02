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
  chmod 777 kadmin
fi

sudo kadmin -l ext -k kadmin/admin.keytab admin/admin

if [ -d "kerberosservice" ]; then
  echo "kerberosservice folder already exists."
else
  # Create the kadmin folder
  mkdir kerberosservice
  echo "kerberosservice folder created."
  chmod 777 kerberosservice
fi

mkdir -p py
cat <<EOF > py/server-config.yaml
ldap:
  server: "ldap://openldap.heimdal.uni-magdeburg.de"
  user: "cn=admin,dc=openldap,dc=heimdal,dc=uni-magdeburg,dc=de"
  password: "Abc1234"
  search_base: "dc=openldap,dc=heimdal,dc=uni-magdeburg,dc=de"
  search_filter: "(objectClass=domainAccount)"
  attributes: ["userAccountControl", "accountExpires", "uid", "cn", "employeeID"]
  domain: "HEIMDAL.UNI-MAGDEBURG.DE"
  keytab: "admin.keytab"
ad:
  server: "ldap://kerberos.uni-magdeburg.de"
  user: "cn=Administrator,cn=Users,dc=kerberos,dc=uni-magdeburg,dc=de"
  password: "Abc1234"
  search_base: "dc=kerberos,dc=uni-magdeburg,dc=de"
  search_filter: "(objectClass=user)"
  attributes: ["userAccountControl", "accountesExpires", "uid", "cn", "employeeID"]
  domain: "KERBEROS.UNI-MAGDEBURG.DE"
  keytab: "svc_passchange.keytab"
EOF
