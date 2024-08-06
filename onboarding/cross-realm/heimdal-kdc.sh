#!/bin/bash

# Define the realm and admin credentials


REALM="HEIMDAL.UNI-MAGDEBURG.DE"
KDC_HOSTNAME="heimdalserver.heimdal.uni-magdeburg.de"
REPLICA_KDC_HOSTNAME="replica.heimdal.uni-magdeburg.de"

AD_REALM="KERBEROS.UNI-MAGDEBURG.DE"
AD_KDC="kerberos.uni-magdeburg.de"
ADMIN_PRINCIPAL="admin/admin"

DOMAIN="heimdal.uni-magdeburg.de"
CA_SUBJECT="CN=CA,${BASE_DN}"
KDC_SUBJECT="uid=heimdal,${BASE_DN}" # Anpassen, je nach Servernamen 
USER_SUBJECT="uid=testuser123,${BASE_DN}" # Anpassen 
PKINIT_PRINCIPAL="testuser123@${REALM}" # Anpassen

ENCRYPTION_TYPE="aes256-cts-hmac-sha1-96"
KRB_PASSWORD="Abc1234"
ADMIN_PRINCIPAL="admin/admin"
ADMIN_PASSWORD="Abc1234"

LDAP_DOMAIN="openldap.heimdal.uni-magdeburg.de"

PKINIT_DIR="/etc/heimdal-kdc/pkinit"
CA_CERT="${PKINIT_DIR}/ca.pem"
KDC_CERT="${PKINIT_DIR}/kdc.pem"
USER_CERT="${PKINIT_DIR}/user.pem"
USER_KEY="${PKINIT_DIR}/user.key"

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
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv python3-pip heimdal-kdc heimdal-clients openssl heimdal-dev apache2 libapache2-mod-auth-gssapi

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
        kdc = $AD_KDC
        admin_server = $AD_KDC
        default_domain = $AD_REALM
    }
[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
    .$AD_KDC = $AD_REALM
    $AD_KDC = $AD_REALM
[logging]
        kdc = FILE:/var/log/krb5kdc.log
        default = FILE:/var/log/krb5lib.log
EOF

# Check if ports 754 and 88 are already in /etc/heimdal-kdc/kdc.conf under [kdc]
if ! grep -q "ports = 754, 88, 464" /etc/heimdal-kdc/kdc.conf; then
    echo "Configuring /etc/heimdal-kdc/kdc.conf to listen on ports 754, 464, and 88..."
    sudo awk '/\[kdc\]/ { print; print "    ports = 754, 88, 464"; next }1' /etc/heimdal-kdc/kdc.conf > /etc/heimdal-kdc/kdc.conf.new
    sudo mv /etc/heimdal-kdc/kdc.conf.new /etc/heimdal-kdc/kdc.conf
else
    echo "Ports are already configured in /etc/heimdal-kdc/kdc.conf"
fi

# Check if PKINIT configuration is already in /etc/heimdal-kdc/kdc.conf under [kdc]
if ! grep -q "enable-pkinit = yes" /etc/heimdal-kdc/kdc.conf; then
    echo "Adding PKINIT configuration to /etc/heimdal-kdc/kdc.conf..."
    sudo awk '/\[kdc\]/ { print; print "    enable-pkinit = yes\n    pkinit_identity = FILE:'"$KDC_CERT"'\n    pkinit_anchors = FILE:'"$CA_CERT"'\n    pkinit_allow_proxy_certificate = false\n    pkinit_win2k_require_binding = yes"; next }1' /etc/heimdal-kdc/kdc.conf > /etc/heimdal-kdc/kdc.conf.new
    sudo mv /etc/heimdal-kdc/kdc.conf.new /etc/heimdal-kdc/kdc.conf
else
    echo "PKINIT configuration is already present in /etc/heimdal-kdc/kdc.conf"
fi



# Add entry to /etc/heimdal-kdc/kadmin.acl for admin/admin
echo "Adding entry to /etc/heimdal-kdc/kadmind.acl for admin/admin..."
echo "admin/admin all,get-keys" | sudo tee -a /etc/heimdal-kdc/kadmind.acl

# Create directories for PKINIT certificates
echo "Creating directories for PKINIT certificates..."
sudo mkdir -p $PKINIT_DIR

# Issue the CA certificate
echo "Issuing CA certificate..."
hxtool issue-certificate --self-signed --issue-ca --generate-key=rsa --subject="$CA_SUBJECT" --lifetime=10years --certificate="FILE:ca.pem"
sudo mv ca.pem $CA_CERT

# Issue the KDC certificate
echo "Issuing KDC certificate..."
hxtool issue-certificate --ca-certificate=FILE:$CA_CERT --generate-key=rsa --type="pkinit-kdc" --pk-init-principal="krbtgt/${REALM}@${REALM}" --subject="$KDC_SUBJECT" --certificate="FILE:kdc.pem"
sudo mv kdc.pem $KDC_CERT

# Issue the user certificate
echo "Issuing user certificate..."
hxtool issue-certificate --ca-certificate=FILE:$CA_CERT --generate-key=rsa --type="pkinit-client" --pk-init-principal="$PKINIT_PRINCIPAL" --subject="$USER_SUBJECT" --certificate="FILE:user.pem"
sudo mv user.pem $USER_CERT

# Convert and move CA private key
echo "Extracting and moving CA private key..."
openssl pkey -in $CA_CERT -out ca.key
sudo mv ca.key ${PKINIT_DIR}/ca.key

# Convert and move user private key
echo "Extracting and moving user private key..."
openssl pkey -in $USER_CERT -out user.key
sudo mv user.key $USER_KEY

# Move user.pem and user.key to the current directory
echo "Moving user.pem and user.key to the current directory..."
sudo mv $USER_CERT $CURRENT_DIR/user.pem
sudo mv $USER_KEY $CURRENT_DIR/user.key

sudo cp $CA_CERT /etc/ssl/certs/

# Start the KDC service
echo "Restarting the Heimdal KDC service..."
sudo systemctl restart heimdal-kdc
sudo systemctl enable heimdal-kdc

# Add principals using kadmin -l
sudo kadmin -l add --use-defaults -p $ADMIN_PASSWORD krbtgt/$AD_REALM
sudo kadmin -l add --use-defaults -p $ADMIN_PASSWORD krbtgt/$REALM@$AD_REALM
sudo kadmin -l add --use-defaults -p $ADMIN_PASSWORD admin/admin
sudo kadmin -l add --use-defaults -p $ADMIN_PASSWORD testuser123
sudo kadmin -l add --use-defaults -p $ADMIN_PASSWORD testuser1234
sudo kadmin -l add --use-defaults -p $ADMIN_PASSWORD ldapbinduser

# Test PKINIT authentication
echo "Testing PKINIT authentication..."
sudo chown admin-test:admin-test $CURRENT_DIR/user.key
sudo chown admin-test:admin-test $CURRENT_DIR/user.pem

echo "Requesting ticket for sudo User..." 
kinit -C FILE:$CURRENT_DIR/user.pem,$CURRENT_DIR/user.key testuser123@$REALM 

echo "Kerberos setup completed."

# manuell: kinit -C FILE:user.pem,user.key testuser123@HEIMDAL.UNI-MAGDEBURG.DE

# heimdal-dev, pip install setuptools


if ! grep -q "<Directory \"/var/www/html\">" /etc/apache2/sites-available/000-default.conf; then
    echo "Adding GSSAPI configuration to /etc/apache2/sites-available/000-default.conf..."
    sudo awk '/<VirtualHost \*:80>/ {
        print
        print "    <Directory \"/var/www/html\">"
        print "        AuthType GSSAPI"
        print "        Authname \"Kerberos Login\""
        print "        GssapiCredStore keytab:/etc/httpd.keytab"
        print "        GssapiAllowedMech krb5"
        print "        GssapiLocalName On"
        print "        GssapiSSLonly Off"
        print "        Require valid-user"
        print "    </Directory>"
        next
    }
    1
    ' /etc/apache2/sites-available/000-default.conf > /tmp/000-default.conf.new
    sudo mv /tmp/000-default.conf.new /etc/apache2/sites-available/000-default.conf
else
    echo "GSSAPI configuration is already present in /etc/apache2/sites-available/000-default.conf"
fi

sudo kadmin -l add -r --use-defaults HTTP/$KDC_HOSTNAME@$REALM
sudo kadmin -l ext -k /etc/httpd.keytab HTTP/$KDC_HOSTNAME@$REALM
sudo chown www-data:www-data /etc/httpd.keytab
sudo chmod 600 /etc/httpd.keytab

sudo systemctl restart apache2

# curl --negotiate -u : http://$KDC_HOSTNAME

# manual Installation für Kadmin Interface
hostnamectl set-hostname $KDC_HOSTNAME