#!/bin/bash

# Set variables
LDAP_DOMAIN="openldap.uni-magdeburg.de"
ADMIN_PASSWORD="Abc1234"
HOSTNAME="client.uni-magdeburg.de"

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libsss-sudo sssd-ldap autofs autofs-ldap ldap-utils 
sudo hostnamectl set-hostname $HOSTNAME

# Function to convert URL to base DN
url_to_base_dn() {
    local url=$1
    local uppercase_dc=$2
    local IFS='.'
    read -ra ADDR <<< "$url"
    local dn=""
    for i in "${ADDR[@]}"; do
        if [ -z "$dn" ]; then
            if [ "$uppercase_dc" == "true" ]; then
                dn="DC=$i"
            else
                dn="dc=$i"
            fi
        else
            if [ "$uppercase_dc" == "true" ]; then
                dn="$dn,DC=$i"
            else
                dn="$dn,dc=$i"
            fi
        fi
    done
    echo "$dn"
}

# Get base DNs
BASE_DN=$(url_to_base_dn "$LDAP_DOMAIN" "false")

# SSSD configuration
sudo bash -c "cat > /etc/sssd/sssd.conf" <<EOF
[sssd]
config_file_version = 2
domains = $LDAP_DOMAIN
services = nss, pam, sudo

[domain/$LDAP_DOMAIN]
id_provider = ldap
sudo_provider = ldap 

ldap_uri = ldap://$LDAP_DOMAIN
ldap_user_search_base = ou=Domain Users,$BASE_DN
ldap_user_object_class = domainAccount

access_provider = ldap
ldap_access_filter = (userAccountControl=512)

ldap_group_search_base = ou=Groups,$BASE_DN
ldap_group_object_class = customGroup
ldap_group_name = cn

auth_provider = ldap
ldap_id_use_start_tls = false
ldap_tls_reqcert = never
ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt
ldap_default_bind_dn = uid=ldapbinduser,ou=Users,$BASE_DN
ldap_auth_disable_tls_never_use_in_production = true
ldap_default_authtok_type = password
ldap_default_authtok = $ADMIN_PASSWORD

ldap_user_uuid = entryUUID
ldap_user_uid_number = uidNumber
ldap_user_gid_number = gidNumber
ldap_group_gid_number = gidNumber
ldap_group_uuid = entryUUID
ldap_user_name = uid

debug_level = 9
use_fully_qualified_names = false
enumerate = true

override_shell = /bin/bash
override_homedir = /home/%u


[sudo]
EOF

# Secure the SSSD configuration file
sudo chmod 600 /etc/sssd/sssd.conf
sudo chown root:root /etc/sssd/sssd.conf

pam-auth-update --enable mkhomedir
sudo systemctl restart sssd
