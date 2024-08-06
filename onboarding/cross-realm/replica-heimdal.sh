#!/bin/bash

# Datenbank und Master-Key müssen nach /var/lib/heimdal-kdc/ von Master-KDC kopiert  werden
# /etc/krb5.keytab kann entweder lokal erstellt werden oder ebenfalls von Master-KDC kopiert werden

# Define the realm and admin credentials
DOMAIN="uni-magdeburg.de"

REALM="HEIMDAL.UNI-MAGDEBURG.DE"
KDC_HOSTNAME="heimdalserver.heimdal.uni-magdeburg.de"
REPLICA_KDC_HOSTNAME="replica.heimdal.uni-magdeburg.de"

AD_REALM="KERBEROS.UNI-MAGDEBURG.DE"
AD_KDC="ad100.kerberos.uni-magdeburg.de"

ADMIN_PRINCIPAL="admin/admin"
ADMIN_PASSWORD="Abc1234"

LDAP_DNS="openldap.heimdal.uni-magdeburg.de"

# Convert domain to base DN
IFS='.' read -r -a DOMAIN_PARTS <<< "$DOMAIN"
BASE_DN=$(printf ",DC=%s" "${DOMAIN_PARTS[@]}")
BASE_DN="${BASE_DN:1}"

# Escape dots in REALM and AD_REALM for auth_to_local rules
ESCAPED_REALM=$(echo "$REALM" | sed 's/\./\\./g')
ESCAPED_AD_REALM=$(echo "$AD_REALM" | sed 's/\./\\./g')

# Get the current directory
CURRENT_DIR=$(pwd)

echo "Preseeding debconf database for Kerberos..."
sudo debconf-set-selections <<EOF
krb5-config krb5-config/default_realm string $REALM
krb5-config krb5-config/admin_server string $KDC_HOSTNAME
krb5-config krb5-config/kerberos_servers string $KDC_HOSTNAME
EOF

# Update package lists
echo "Updating package lists..."
sudo apt-get update

# Install necessary packages non-interactively
echo "Installing Kerberos server and clients..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y heimdal-kdc heimdal-clients openssl heimdal-dev

# Configure the realm in /etc/krb5.conf
sudo bash -c "cat > /etc/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    pkinit_anchors = FILE:/etc/ssl/certs/ca.pem
[realms]
    $REALM = {
        kdc = $KDC_HOSTNAME
        kdc = $REPLICA_KDC_HOSTNAME
        admin_server = $KDC_HOSTNAME
        default_domain = $REALM
        auth_to_local = RULE:[1:\$1@\$0](.*@$ESCAPED_AD_REALM)s/@.*//
        auth_to_local = RULE:[1:\$1@\$0](.*@$ESCAPED_REALM)s/@.*//
    }
    $AD_REALM = {
        kdc = $AD_DOMAIN_LOWERCASE
        admin_server = $AD_DOMAIN_LOWERCASE
        default_domain = $AD_REALM
    }
[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
    .$AD_DOMAIN_LOWERCASE = $AD_REALM
    $AD_DOMAIN_LOWERCASE = $AD_REALM
[logging]
        kdc = FILE:/var/log/krb5kdc.log
        default = FILE:/var/log/krb5lib.log
EOF

# Check if ports 754 and 88 are already in /etc/heimdal-kdc/kdc.conf under [kdc]
if ! grep -q "ports = 754, 88, 464" /etc/heimdal-kdc/kdc.conf; then
    echo "Configuring /etc/heimdal-kdc/kdc.conf to listen on ports 754, 464 and 88..."
    sudo awk '/\[kdc\]/ { print; print "    ports = 754, 88, 464"; next }1' /etc/heimdal-kdc/kdc.conf > /etc/heimdal-kdc/kdc.conf.new
    sudo mv /etc/heimdal-kdc/kdc.conf.new /etc/heimdal-kdc/kdc.conf
else
    echo "Ports are already configured in /etc/heimdal-kdc/kdc.conf"
fi

# Add entry to /etc/heimdal-kdc/kadmin.acl for admin/admin
echo "Adding entry to /etc/heimdal-kdc/kadmind.acl for admin/admin..."
echo "admin/admin all,get-keys" | sudo tee -a /etc/heimdal-kdc/kadmind.acl


# Start the KDC service
echo "Restarting the Heimdal KDC service..."
sudo systemctl restart heimdal-kdc
sudo systemctl enable heimdal-kdc

# Add principals using kadmin -l
sudo kadmin -l add --use-defaults -p $ADMIN_PASSWORD admin/admin


echo "Requesting ticket for sudo User..." 
kinit -C FILE:$CURRENT_DIR/user.pem,$CURRENT_DIR/user.key testuser123@$REALM 

echo "Kerberos setup completed."

sudo hostnamectl set-hostname $REPLICA_KDC_HOSTNAME
