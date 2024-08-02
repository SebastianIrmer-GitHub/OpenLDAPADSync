#!/bin/bash

# Set variables
REALM="HEIMDAL.UNI-MAGDEBURG.DE"
AD_REALM="KERBEROS.UNI-MAGDEBURG.DE"
LDAP_DOMAIN="openldap.heimdal.uni-magdeburg.de"
KDC_HOSTNAME="heimdalserver.heimdal.uni-magdeburg.de"
REPLICA_KDC_HOSTNAME="replica.heimdal.uni-magdeburg.de"
DOMAIN="heimdal.uni-magdeburg.de"
ADMIN_PRINCIPAL="admin/admin"
ADMIN_PASSWORD="Abc1234"
HOSTNAME="client.heimdal.uni-magdeburg.de"

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libsss-sudo cifs-utils sssd-ldap sssd-krb5 autofs autofs-ldap ldap-utils expect heimdal-clients
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
AD_BASE_DN=$(url_to_base_dn "$AD_REALM" "true")

# Kerberos configuration
sudo bash -c "cat > /etc/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    pkinit_anchors = FILE:/etc/ssl/certs/ca.pem
    
[realms]
    $REALM = {
        kdc = $KDC_HOSTNAME
        kdc = $REPLICA_KDC_HOSTNAME
        admin_server = $KDC_HOSTNAME
        default_realm = $REALM
    }
[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
EOF

# Set hostname
sudo hostnamectl set-hostname $HOSTNAME
retrieve_ticket() {
  local cmd=$1
  expect <<EOF
    spawn sudo $cmd
    expect "Password for $ADMIN_PRINCIPAL@$REALM:"
    send "$ADMIN_PASSWORD\r"
    expect eof
EOF
}

# First ticket retrieval, Host Ticket for KDC Validation
retrieve_ticket "ktutil get -p $ADMIN_PRINCIPAL -e aes256-cts-hmac-sha1-96 host/$HOSTNAME"

# Add principal to keytab, Bind Ticket to Search LDAP 
retrieve_ticket "kadmin -p $ADMIN_PRINCIPAL ext -k /etc/sssd/sssd.keytab ldapbinduser"

# Secure the keytab file
sudo chmod 600 /etc/krb5.keytab
sudo chown root:root /etc/krb5.keytab

# Secure the keytab file
sudo chmod 600 /etc/sssd/sssd.keytab
sudo chown root:root /etc/sssd/sssd.keytab

# SSSD configuration
sudo bash -c "cat > /etc/sssd/sssd.conf" <<EOF
[sssd]
config_file_version = 2
domains = $LDAP_DOMAIN
services = nss, pam, autofs, sudo

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

ldap_sasl_mech = GSSAPI
ldap_sasl_authid = ldapbinduser
ldap_krb5_keytab = /etc/sssd/sssd.keytab

auth_provider = krb5
krb5_server = $KDC_HOSTNAME
krb5_kpasswd = $KDC_HOSTNAME
krb5_realm = $REALM
krb5_validate = True
cache_credentials = True

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
krb5_ccname_template = FILE:%d/krb5cc_%U

autofs_provider = ldap
ldap_autofs_search_base = ou=automount,$BASE_DN
ldap_autofs_map_object_class = automountMap
ldap_autofs_entry_object_class = automount
ldap_autofs_map_name = ou
ldap_autofs_entry_key = cn
ldap_autofs_entry_value = automountInformation

[sudo]

[autofs]
EOF

# Secure the SSSD configuration file
sudo chmod 600 /etc/sssd/sssd.conf
sudo chown root:root /etc/sssd/sssd.conf

pam-auth-update --enable mkhomedir
sudo systemctl restart sssd
