#!/bin/bash

# Variables
LDAP_DOMAIN="openldap.heimdal.uni-magdeburg.de"
LDAP_ORG="Example Organization"
LDAP_ADMIN_PASS="Abc1234"
REALM="HEIMDAL.UNI-MAGDEBURG.DE"
ADMIN_PRINCIPAL="admin/admin"
KDC_HOSTNAME="heimdalserver.heimdal.uni-magdeburg.de"

REPLICA_KDC_HOSTNAME="replica.heimdal.uni-magdeburg.de"
DOMAIN="heimdal.uni-magdeburg.de"
ENCRYPTION_TYPE="aes256-cts-hmac-sha1-96"
KRB_PASSWORD="Abc1234"
AD_DOMAIN="kerberos.uni-magdeburg.de"

# Update package lists
echo "Updating package lists..."
sudo apt-get update

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

BASE_DN=$(url_to_base_dn "$LDAP_DOMAIN" "false")
AD_BASE_DN=$(url_to_base_dn "$AD_DOMAIN" "true")



# Install OpenLDAP server and client
# Preseed debconf database with necessary password configuration
echo "Preseeding debconf database for passwords..."
sudo debconf-set-selections <<EOF
slapd slapd/password1 password $LDAP_ADMIN_PASS
slapd slapd/password2 password $LDAP_ADMIN_PASS
EOF

# Update package lists again
echo "Updating package lists again..."
sudo apt-get update

# Install OpenLDAP server and client non-interactively
echo "Installing OpenLDAP server and client..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y autofs autofs-ldap  python3-venv python3-pip python3-ldap3 openjdk-8-jdk slapd ldap-utils sasl2-bin libsasl2-2 libsasl2-modules libsasl2-modules-gssapi-mit expect heimdal-clients

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

# Configure slapd (non-interactive)
echo "Configuring slapd..."
sudo debconf-set-selections <<EOF
slapd slapd/no_configuration boolean false
slapd slapd/domain string $LDAP_DOMAIN
slapd shared/organization string "$LDAP_ORG"
slapd slapd/password1 password $LDAP_ADMIN_PASS
slapd slapd/password2 password $LDAP_ADMIN_PASS
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
EOF

sudo dpkg-reconfigure -f noninteractive slapd


echo "Downloading LSC..."

sudo wget https://lsc-project.org/archives/lsc_2.1.6-1_all.deb
sudo dpkg -i lsc_2.1.6-1_all.deb

echo "Creating LSC Files..." 

apparmor_file="/etc/apparmor.d/usr.sbin.slapd"
audit_log_line="/var/log/openldap/auditlog.log rw,"

add_audit_log_line() {

    # Check if the line already exists (either commented or uncommented)
    if grep -qF "# $audit_log_line" "$apparmor_file"; then
        sudo sed -i "s|# $audit_log_line|$audit_log_line|" "$apparmor_file"
    elif ! grep -qF "$audit_log_line" "$apparmor_file"; then

        # Insert the line under the /usr/sbin/slapd { section
        sudo sed -i "/\/usr\/sbin\/slapd/,+1 { /{/ a\\
  $audit_log_line
        }" "$apparmor_file"
        
        echo "Added audit log line to $apparmor_file"
    else
        echo "Audit log line already exists in $apparmor_file"
    fi
}
add_audit_log_line

sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.slapd

cat <<EOF > /etc/lsc/lsc.xml 
<?xml version="1.0" ?>
<lsc xmlns="http://lsc-project.org/XSD/lsc-core-2.1.xsd" revision="0">
    <connections>
        <ldapConnection>
            <name>ldap-OpenLDAP-conn</name>
            <url>ldap://$LDAP_DOMAIN:389/$BASE_DN</url>
            <username>cn=admin,$BASE_DN</username>
            <password>Abc1234</password>
            <authentication>SIMPLE</authentication>
            <referral>IGNORE</referral>
            <derefAliases>NEVER</derefAliases>
            <version>VERSION_3</version>
            <pageSize>5000</pageSize>
            <factory>com.sun.jndi.ldap.LdapCtxFactory</factory>
        </ldapConnection>
        <ldapConnection>
            <name>ldap-AD-conn</name>
            <url>ldap://$AD_DOMAIN:389/$AD_BASE_DN</url>
            <username>CN=Administrator,CN=Users,$AD_BASE_DN</username>
            <password>Abc1234</password>
            <authentication>SIMPLE</authentication>
            <referral>IGNORE</referral>
            <derefAliases>NEVER</derefAliases>
            <version>VERSION_3</version>
            <pageSize>5000</pageSize>
            <factory>com.sun.jndi.ldap.LdapCtxFactory</factory>
            <recursiveDelete>true</recursiveDelete>
        </ldapConnection>
    </connections>
    <tasks>
        <task>
            <name>a-syncOU</name>
            <bean>org.lsc.beans.SimpleBean</bean>
            <asyncLdapSourceService>
                <name>ldap-src-OU-service</name>
                <connection reference="ldap-OpenLDAP-conn" />
                <baseDn>ou=Domain Users,$BASE_DN</baseDn>
                <pivotAttributes>
                    <string>ouID</string>
                </pivotAttributes>
                <fetchedAttributes>
                    <string>ou</string>
                    <string>ouID</string>
                    <string>ouParentID</string>
                    <string>description</string>
                </fetchedAttributes>
                <getAllFilter><![CDATA[(objectClass=organizationalUnit)]]></getAllFilter>
                <getOneFilter><![CDATA[(&(objectClass=organizationalUnit)(ouID={ouID}))]]></getOneFilter>
                <cleanFilter><![CDATA[(&(objectClass=organizationalUnit)(ouID={orgUnitID}))]]></cleanFilter>
                <synchronizingAllWhenStarting>true</synchronizingAllWhenStarting>
                <serverType>OpenLDAP</serverType>           
            </asyncLdapSourceService>
            <ldapDestinationService>
                <name>ldap-dst-OU-service</name>
                <connection reference="ldap-AD-conn" />
                <baseDn>ou=Domain Users,$AD_BASE_DN</baseDn>
                <pivotAttributes>
                    <string>orgUnitID</string>
                </pivotAttributes>
                <fetchedAttributes>
                    <string>ou</string>
                    <string>orgUnitID</string>
                    <string>orgUnitParentID</string>
                    <string>objectclass</string>
                    <string>description</string>
                </fetchedAttributes>
                <getAllFilter><![CDATA[(objectClass=organizationalUnit)]]></getAllFilter>
                <getOneFilter><![CDATA[(&(objectClass=organizationalUnit)(orgUnitID={ouID}))]]></getOneFilter>
            </ldapDestinationService>
            <propertiesBasedSyncOptions>
                <mainIdentifier>js:removeBaseDN(srcBean.getMainIdentifier(), "$BASE_DN", "$AD_BASE_DN")</mainIdentifier>
                <defaultDelimiter>;</defaultDelimiter>
                <defaultPolicy>FORCE</defaultPolicy>
                <conditions>
                    <create>true</create>
                    <update>true</update>
                    <changeId>true</changeId>
                </conditions>
                 <dataset>
                    <name>objectclass</name>
                    <policy>KEEP</policy>
                    <createValues>
                        <string>"organizationalUnit"</string>
                        <string>"top"</string>
                    </createValues>
                </dataset>
                <dataset>
                    <name>orgUnitID</name>
                    <policy>KEEP</policy>
                    <createValues>
                        <string>srcBean.getDatasetFirstValueById("ouID")</string>
                    </createValues>
                </dataset>  
                 <dataset>
                    <name>orgUnitParentID</name>
                    <policy>KEEP</policy>
                    <createValues>
                        <string>srcBean.getDatasetFirstValueById("ouParentID")</string>
                    </createValues>
                </dataset>  
            </propertiesBasedSyncOptions>
            <scriptInclude>
                <string>get_dn.js</string>
            </scriptInclude>
        </task>
        <task>
            <name>x-createUsers</name>
            <bean>org.lsc.beans.SimpleBean</bean>
            <asyncLdapSourceService>
                <name>ldap-src-service</name>
                <connection reference="ldap-OpenLDAP-conn" />
                <baseDn>ou=Domain Users,$BASE_DN</baseDn>
                <pivotAttributes>
                    <string>uid</string>
                </pivotAttributes>
                <fetchedAttributes>
                    <string>cn</string>
                    <string>description</string>
                    <string>givenName</string>
                    <string>mail</string>
                    <string>sn</string>
                    <string>uid</string>
                    <string>gender</string>
                    <string>employeeID</string>
                    <string>uidNumber</string>
                    <string>gidNumber</string>
                    <string>userStatus</string>
                    <string>userStatusValidFrom</string>
                    <string>accountExpires</string>
                </fetchedAttributes>
                <getAllFilter><![CDATA[(objectClass=domainAccount)]]></getAllFilter>
                <getOneFilter><![CDATA[(&(objectClass=domainAccount)(uid={uid}))]]></getOneFilter>
                <cleanFilter><![CDATA[(&(objectClass=domainAccount)(uid={sAMAccountName}))]]></cleanFilter>
                <synchronizingAllWhenStarting>true</synchronizingAllWhenStarting>
                <serverType>OpenLDAP</serverType>
            </asyncLdapSourceService>
            <ldapDestinationService>
                <name>ldap-dst-service</name>
                <connection reference="ldap-AD-conn" />
                <baseDn>ou=Domain Users,$AD_BASE_DN</baseDn>
                <pivotAttributes>
                    <string>sAMAccountName</string>
                </pivotAttributes>
                <fetchedAttributes>
                    <string>cn</string>
                    <string>givenName</string>
                    <string>objectclass</string>
                    <string>sAMAccountName</string>
                    <string>userPrincipalName</string>
                    <string>altSecurityIdentities</string>
                    <string>userAccountControl</string>
                    <string>sn</string>
                    <string>gender</string>
                    <string>employeeID</string>
                    <string>pwdLastSet</string>
                    <string>uidNumber</string>
                    <string>gidNumber</string>
                    <string>userStatus</string>
                    <string>userStatusValidFrom</string>
                    <string>accountExpires</string>
                </fetchedAttributes>
                <getAllFilter><![CDATA[(objectClass=user)]]></getAllFilter>
                <getOneFilter><![CDATA[(&(objectClass=user)(sAMAccountName={uid}))]]></getOneFilter>
            </ldapDestinationService>
            <propertiesBasedSyncOptions>
                <mainIdentifier>js:getDnOfUser(srcBean.getMainIdentifier(), srcBean.getDatasetFirstValueById("cn"), "$BASE_DN", "$AD_BASE_DN")</mainIdentifier>
                <defaultDelimiter>;</defaultDelimiter>
                <defaultPolicy>KEEP</defaultPolicy>
                <conditions>
                    <create>true</create>
                    <update>false</update>
                    <delete>false</delete>
                    <changeId>false</changeId>
                </conditions>
                <dataset>
                    <name>userStatusValidFrom</name>
                    <policy>KEEP</policy>
                    <forceValues>
                        <string>js:convertOpenLDAPToAD(srcBean.getDatasetFirstValueById("userStatusValidFrom"))</string>
                    </forceValues>
                </dataset>
                <dataset>
                    <name>objectclass</name>
                    <policy>KEEP</policy>
                    <createValues>
                        <string>"user"</string>
                        <string>"organizationalPerson"</string>
                        <string>"person"</string>
                        <string>"top"</string>
                    </createValues>
                </dataset>
                <dataset>
                    <name>sAMAccountName</name>
                    <policy>KEEP</policy>
                    <createValues>
                        <string>srcBean.getDatasetFirstValueById("uid")</string>
                    </createValues>
                </dataset>
                  <dataset>
                    <name>accountExpires</name>
                    <policy>KEEP</policy>
                    <createValues>
                        <string>js:getAccountExpires(srcBean.getDatasetFirstValueById("accountExpires"))</string>
                    </createValues>
                </dataset>
                <dataset>
                    <name>userPrincipalName</name>
                    <policy>KEEP</policy>
                    <createValues>
                        <string>srcBean.getDatasetFirstValueById("uid") + "@$AD_DOMAIN"</string>
                    </createValues>
                </dataset>
                <dataset>
                    <name>altSecurityIdentities</name>
                    <policy>KEEP</policy>
                    <createValues>
                        <string>"Kerberos:" + srcBean.getDatasetFirstValueById("uid") + "@$REALM"</string>
                    </createValues>
                </dataset>
                <dataset>
                    <name>userAccountControl</name>
                    <policy>KEEP</policy>
                    <createValues>
                        <string>"2"</string>
                    </createValues>
                </dataset>

            </propertiesBasedSyncOptions>
            <scriptInclude>
                <string>get_dn.js</string>
            </scriptInclude>
        </task>
     <task>
            <name>x-updateUsers</name>
            <bean>org.lsc.beans.SimpleBean</bean>
            <asyncLdapSourceService>
                <name>ldap-update-from-service</name>
                <connection reference="ldap-OpenLDAP-conn" />
                <baseDn>ou=Domain Users,$BASE_DN</baseDn>
                <pivotAttributes>
                    <string>uid</string>
                </pivotAttributes>
                <fetchedAttributes>
                    <string>cn</string>
                    <string>description</string>
                    <string>givenName</string>
                    <string>mail</string>
                    <string>sn</string>
                    <string>uid</string>
                    <string>employeeID</string>
                    <string>uidNumber</string>
                    <string>gidNumber</string>
                    <string>userStatus</string>
                    <string>gender</string>
                    <string>userAccountControl</string>
                    <string>userStatusValidFrom</string>
                    <string>accountExpires</string>
                </fetchedAttributes>
                <getAllFilter><![CDATA[(objectClass=domainAccount)]]></getAllFilter>
                <getOneFilter><![CDATA[(&(objectClass=domainAccount)(uid={uid}))]]></getOneFilter>
                <cleanFilter><![CDATA[(&(objectClass=domainAccount)(uid={sAMAccountName}))]]></cleanFilter>
                <synchronizingAllWhenStarting>true</synchronizingAllWhenStarting>
                <serverType>OpenLDAP</serverType>   
            </asyncLdapSourceService>
            <ldapDestinationService>
                <name>ldap-update-to-service</name>
                <connection reference="ldap-AD-conn" />
                <baseDn>ou=Domain Users,$AD_BASE_DN</baseDn>
                <pivotAttributes>
                    <string>sAMAccountName</string>
                </pivotAttributes>
                <fetchedAttributes>
                    <string>cn</string>
                    <string>givenName</string>
                    <string>sAMAccountName</string>
                    <string>userPrincipalName</string>
                    <string>altSecurityIdentities</string>
                    <string>userAccountControl</string>
                    <string>sn</string>
                    <string>gender</string>
                    <string>employeeID</string>
                    <string>uidNumber</string>
                    <string>gidNumber</string>
                    <string>userStatus</string>
                    <string>userStatusValidFrom</string>
                    <string>accountExpires</string>
                    <string>pwdLastSet</string> 
                </fetchedAttributes>
                <getAllFilter><![CDATA[(objectClass=user)]]></getAllFilter>
                <getOneFilter><![CDATA[(&(objectClass=user)(sAMAccountName={uid}))]]></getOneFilter>
            </ldapDestinationService>
            <propertiesBasedSyncOptions>
                <mainIdentifier>js:getDnOfUser(srcBean.getMainIdentifier(), srcBean.getDatasetFirstValueById("cn"), "$BASE_DN", "$AD_BASE_DN")</mainIdentifier>
                <defaultDelimiter>;</defaultDelimiter>
                <defaultPolicy>FORCE</defaultPolicy>
                <conditions>
                    <create>false</create>
                    <update>true</update>
                    <changeId>true</changeId>
                </conditions>
                <dataset>
                    <name>userStatusValidFrom</name>
                    <policy>FORCE</policy>
                    <forceValues>
                        <string>js:convertOpenLDAPToAD(srcBean.getDatasetFirstValueById("userStatusValidFrom"))</string>
                    </forceValues>
                </dataset>
                <dataset>
                    <name>accountExpires</name>
                    <policy>FORCE</policy>
                    <forceValues>
                        <string>js:getAccountExpires(srcBean.getDatasetFirstValueById("accountExpires"))</string>
                 </forceValues>
                </dataset>
                <dataset>
                    <name>sAMAccountName</name>
                    <policy>FORCE</policy>
                    <forceValues>
                        <string>srcBean.getDatasetFirstValueById("uid")</string>
                    </forceValues>
                </dataset>
                <dataset>
                    <name>userPrincipalName</name>
                    <policy>FORCE</policy>
                    <forceValues>
                        <string>srcBean.getDatasetFirstValueById("uid") + "@$AD_DOMAIN"</string>
                    </forceValues>
                </dataset>
                <dataset>
                    <name>altSecurityIdentities</name>
                    <policy>FORCE</policy>
                    <forceValues>
                        <string>"Kerberos:" + srcBean.getDatasetFirstValueById("uid") + "@$REALM"</string>
                    </forceValues>
                </dataset>
            <dataset>
                <name>userAccountControl</name>
                <policy>FORCE</policy>
                
                <forceValues>
                    <string><![CDATA[
                        js:
                        
                            var pwdLastSet = dstBean.getDatasetFirstValueById("pwdLastSet");
                            var dstUAC = dstBean.getDatasetFirstValueById("userAccountControl");
                            var srcUAC = srcBean.getDatasetFirstValueById("userAccountControl");
                            var value = dstUAC
                            if (pwdLastSet && srcUAC && dstUAC) {
                                
                            // if no pre-auth required would be set, then that should be equally specified here. That will not be implemented here.  

                                if(dstBean.getDatasetFirstValueById("pwdLastSet") > 0 || dstBean.getDatasetFirstValueById("pwdLastSet") == -1) value = srcUAC;

                                if (srcUAC == 2) {
                                    value = 514
                                }
                            }
                            
                            value
                        ]]></string>
                </forceValues>
            </dataset>
            <dataset>
                <name>pwdLastSet</name>
                <policy>KEEP</policy>
            </dataset>
            </propertiesBasedSyncOptions>
            <scriptInclude>
                <string>get_dn.js</string>
            </scriptInclude>
        </task>
        
        <task>
            <name>y-createGroups</name> 
            <bean>org.lsc.beans.SimpleBean</bean>
            <asyncLdapSourceService>
                <name>group-source-service</name>
                <connection reference="ldap-OpenLDAP-conn" />
                <baseDn>ou=Groups,$BASE_DN</baseDn>
                <pivotAttributes>
                    <string>uniqueGroupID</string>
                </pivotAttributes>
                <fetchedAttributes>
                    <string>cn</string>
                    <string>description</string>
                    <string>groupType</string>
                    <string>uniqueGroupID</string>
                    <string>member</string>
                </fetchedAttributes>
                <getAllFilter><![CDATA[(objectClass=customGroup)]]></getAllFilter>
                <getOneFilter><![CDATA[(&(objectClass=customGroup)(uniqueGroupID={uniqueGroupID}))]]></getOneFilter>
                <cleanFilter><![CDATA[(&(objectClass=customGroup)(uniqueGroupID={uniqueGroupID}))]]></cleanFilter>
                <synchronizingAllWhenStarting>true</synchronizingAllWhenStarting>
                <serverType>OpenLDAP</serverType>
            </asyncLdapSourceService>
            <ldapDestinationService>
                <name>group-dst-service</name>
                <connection reference="ldap-AD-conn" />
                <baseDn>ou=Groups,$AD_BASE_DN</baseDn>
                <pivotAttributes>
                    <string>uniqueGroupID</string>
                </pivotAttributes>
                <fetchedAttributes>
                    <string>cn</string>
                    <string>description</string>
                    <string>groupType</string>
                    <string>sAMAccountName</string>
                    <string>objectClass</string>
                    <string>uniqueGroupID</string>
                </fetchedAttributes>
                <getAllFilter><![CDATA[(objectClass=group)]]></getAllFilter>
                <getOneFilter><![CDATA[(&(objectClass=group)(uniqueGroupID={uniqueGroupID}))]]></getOneFilter>
            </ldapDestinationService>
            <propertiesBasedSyncOptions>
                <mainIdentifier>js:getDnOfUser(srcBean.getMainIdentifier(), srcBean.getDatasetFirstValueById("cn"), "$BASE_DN", "$AD_BASE_DN")</mainIdentifier>
                <defaultDelimiter>;</defaultDelimiter>
                <defaultPolicy>KEEP</defaultPolicy>
                <conditions>
                    <create>true</create>
                    <update>true</update>
                    <delete>true</delete>
                    <changeId>true</changeId>
                </conditions>
                <dataset>
                    <name>objectclass</name>
                    <policy>KEEP</policy>
                    <createValues>
                        <string>"group"</string>
                        <string>"top"</string>
                    </createValues>
                </dataset>
                <dataset>
                    <name>sAMAccountName</name>
                    <policy>KEEP</policy>
                    <createValues>
                        <string>srcBean.getDatasetFirstValueById("cn")</string>
                    </createValues>
                </dataset>  
            </propertiesBasedSyncOptions>
            <scriptInclude>
                <string>get_dn.js</string>
            </scriptInclude>
        </task>
    
        <task>
            <name>y-updateGroups</name> 
            <bean>org.lsc.beans.SimpleBean</bean>
            <asyncLdapSourceService>
                <name>group-async-update-source-service</name>
                <connection reference="ldap-OpenLDAP-conn" />
                <baseDn>ou=Groups,$BASE_DN</baseDn>
                <pivotAttributes>
                    <string>uniqueGroupID</string>
                </pivotAttributes>
                <fetchedAttributes>
                    <string>cn</string>
                    <string>description</string>
                    <string>groupType</string>
                    <string>member</string>
                    <string>uniqueGroupID</string>
                </fetchedAttributes>
                <getAllFilter><![CDATA[(objectClass=customGroup)]]></getAllFilter>
                <getOneFilter><![CDATA[(&(objectClass=customGroup)(uniqueGroupID={uniqueGroupID}))]]></getOneFilter>
                <cleanFilter><![CDATA[(&(objectClass=customGroup)(uniqueGroupID={uniqueGroupID}))]]></cleanFilter>
                <synchronizingAllWhenStarting>true</synchronizingAllWhenStarting>
                <serverType>OpenLDAP</serverType>
            </asyncLdapSourceService>
            <ldapDestinationService>
                <name>group-async-update-dst-service</name>
                <connection reference="ldap-AD-conn" />
                <baseDn>ou=Groups,$AD_BASE_DN</baseDn>
                <pivotAttributes>
                    <string>uniqueGroupID</string>
                </pivotAttributes>
                <fetchedAttributes>
                    <string>uniqueGroupID</string>
                    <string>description</string>
                    <string>member</string>
                    <string>sAMAccountName</string>
                    <string>groupType</string>
                    <string>uniqueGroupID</string>
                </fetchedAttributes>
                <getAllFilter><![CDATA[(objectClass=group)]]></getAllFilter>
                <getOneFilter><![CDATA[(&(objectClass=group)(uniqueGroupID={uniqueGroupID}))]]></getOneFilter>
            </ldapDestinationService>
            <propertiesBasedSyncOptions>
                <mainIdentifier>js:getDnOfUser(srcBean.getMainIdentifier(), srcBean.getDatasetFirstValueById("cn"), "$BASE_DN", "$AD_BASE_DN")</mainIdentifier>
                <defaultDelimiter>;</defaultDelimiter>
                <defaultPolicy>FORCE</defaultPolicy>
                <conditions>
                    <create>false</create>
                    <update>true</update>
                    <delete>true</delete>
                </conditions>
                <dataset>
                    <name>groupType</name>
                    <policy>FORCE</policy>
                    <createValues>
                        <string>srcBean.getDatasetFirstValueById("groupType")</string>
                    </createValues>
                </dataset>   
                <dataset>
                    <name>sAMAccountName</name>
                    <policy>FORCE</policy>
                    <forceValues>
                        <string>srcBean.getDatasetFirstValueById("cn")</string>
                    </forceValues>
                </dataset>
                <dataset>
                    <name>member</name>
                    <policy>FORCE</policy>
                    <forceValues>
                        <string><![CDATA[
                                js:
                            var membersSrcDn = srcBean.getDatasetValuesById("member");
                            var membersDstDn = [];
                            function normalizeDN(dn) {
                                return dn.replace(",ou", ",OU").replace("$AD_BASE_DN", "$AD_BASE_DN")
                            }
                            // Process individual members and groups
                            for (var i = 0; i < membersSrcDn.size(); i++) {
                                var memberSrcDn = membersSrcDn.get(i);
                                // Check if the current DN is a group or an individual member
                                var isGroup = memberSrcDn.indexOf("ou=Groups") !== -1;
                                if (isGroup) {
                                    // If it's a group, add the group DN directly
                                    var groupCn = memberSrcDn.split(",")[0].split("=")[1]; // Extract CN of the group
                                    var groupDn = ldap.search("ou=Groups", "(cn=" + groupCn + ")");
                                    if (groupDn.size() == 1) {
                                        membersDstDn.push(normalizeDN(groupDn.get(0) + "," + ldap.getContextDn()));
                                    }
                                } else {
                                    // If it's an individual member, process as before
                                    var uid = "";

                                    try {
                                        uid = srcLdap.attribute(memberSrcDn, "uid").get(0);
                                    } catch(e) {
                                        continue;
                                    }
                                    var destDn = ldap.search("OU=Domain Users", "(sAMAccountName=" + uid + ")");
                                    if (destDn.size() == 0 || destDn.size() > 1) {
                                        continue;
                                    }

                                    var destMemberDn = destDn.get(0) + "," + ldap.getContextDn();
                                    membersDstDn.push(normalizeDN(destMemberDn));
                                }
                            }

                    
                            membersDstDn
                         
                        ]]></string>
                    </forceValues>
                </dataset>
            </propertiesBasedSyncOptions>
            <scriptInclude>
                <string>get_dn.js</string>
            </scriptInclude>
        </task>
    </tasks>
    <security>
    </security>
</lsc>
EOF


cat <<EOF > /etc/lsc/get_dn.js
function replaceCn(dn, newCn) {
    var cnRegex = /(?:CN|cn|uid|cN)=([^,]+)/;
    var match = dn.match(cnRegex);
    if (!match) {
        throw new Error("CN not found in DN: " + dn + " and " + newCn);
    }
    
    return dn.replace(cnRegex, "cn=" + newCn);
}

function removeBaseDN(dn, baseDn, toReplace) {
    return dn.replace(baseDn, toReplace);
}

function getDnOfUser(sourceDn, newCn, baseDn, newBaseDn) {
    var updatedCn = replaceCn(sourceDn, newCn);
    return removeBaseDN(updatedCn, baseDn, newBaseDn);
}

function convertOpenLDAPToAD(openldapTimestamp) {
    // Check if the timestamp ends with 'Z'
    if (openldapTimestamp.endsWith('Z')) {
        // Find the position of the dot, if it exists
        var dotIndex = openldapTimestamp.indexOf('.');
        if (dotIndex !== -1) {
            // If a dot is found, replace everything after the dot (but before 'Z') with '000'
            return openldapTimestamp.substring(0, dotIndex + 1) + '0Z';
        } else {
            // If no dot is found, append '.000' before the 'Z'
            return openldapTimestamp.slice(0, -1) + '.0Z';
        }
    }
    // Return the original timestamp if it doesn't end with 'Z'
    return openldapTimestamp;
}

function getAccountExpiress(ldapTimestamp) {
    var TICKS_PER_MILLISECOND = 10000;
    var EPOCH_DIFFERENCE = 11644473600000;

    var baseTime = ldapTimestamp.split('.')[0];
    var milliseconds = ldapTimestamp.split('.')[1] ? parseInt(ldapTimestamp.split('.')[1].slice(0, -1)) : 0;

    var isoDateString = baseTime.slice(0, 4) + '-' + baseTime.slice(4, 6) + '-' + baseTime.slice(6, 8) +
                        'T' + baseTime.slice(8, 10) + ':' + baseTime.slice(10, 12) + ':' + baseTime.slice(12, 14) +
                        '.' + milliseconds + 'Z';

    var date = new Date(isoDateString);
    if (isNaN(date.getTime())) {
        throw new Error("Invalid date format or value");
    }

    var msSince1970 = date.getTime();
    var msSince1601 = msSince1970 + EPOCH_DIFFERENCE;

    // Ensure the number is within the safe integer range for JavaScript
    var totalIntervals = Math.floor(msSince1601 * TICKS_PER_MILLISECOND / 10000); // scaled down to avoid overflow

    return totalIntervals.toString();
}

function getAccountExpires(ldapTimestamp) {
    // Constants for conversion


    // Check if ldapTimestamp is empty or null
    if (!ldapTimestamp) {
        return "9223372036854775807";
    }

    return ldapTimestamp

}
EOF
echo "Verifying OpenLDAP installation..."

# Create the custom schema file
# Create the custom schema file
sudo ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/ldap/schema/dyngroup.ldif

echo "Creating custom schema file..."
cat <<EOF > /tmp/customSchema.ldif
dn: cn=sshPublicKey,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: sshPublicKey
olcAttributeTypes: ( 1.3.6.1.4.1.24552.500.1.1.1.13 NAME 'sshPublicKey'
    DESC 'MANDATORY: OpenSSH Public key'
    EQUALITY octetStringMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
olcObjectClasses: ( 1.3.6.1.4.1.24552.500.1.1.2.0 NAME 'ldapPublicKey' SUP top AUXILIARY
    DESC 'MANDATORY: OpenSSH LPK objectclass'
    MAY ( sshPublicKey $ uid )
    )

dn: cn=customGroupSchema,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: customGroupSchema
olcObjectIdentifier: customGroupSchema 1.3.6.1.4.1.99998
olcObjectIdentifier: customGroupUserAttrs customGroupSchema:1
olcObjectIdentifier: customGroupUserOCs customGroupSchema:2
olcAttributeTypes: ( customGroupUserAttrs:1 NAME 'groupType' DESC 'groupType' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
olcAttributeTypes: ( customGroupUserAttrs:2 NAME 'uniqueGroupID' DESC 'uniqueGroupID' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE)
olcObjectClasses: ( customGroupUserOCs:1 NAME 'customGroup' DESC 'User Identity in the organization' SUP top STRUCTURAL MUST ( cn $ groupType $ uniqueGroupID ) MAY ( description $ gidNumber $ memberURL $ member $  o $ ou $ owner ) )

dn: cn=ouSchema,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: ouSchema
olcObjectIdentifier: ouSchema 1.3.6.1.4.1.99998
olcObjectIdentifier: ouAttributes ouSchema:3
olcObjectIdentifier: ouOCs ouSchema:4
olcAttributeTypes: ( ouAttributes:1 NAME 'ouID' DESC 'ID of OU' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE userApplications )
olcAttributeTypes: ( ouAttributes:2 NAME 'ouParentID' DESC 'ID of Parent OU' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE userApplications )
olcObjectClasses: ( ouOCs:1 NAME 'customOU' DESC 'Object class for custom user attributes' SUP organizationalUnit STRUCTURAL MUST ( ouID $ ouParentID $ ou ) )

dn: cn=domainUserSchema,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: domainUserSchema
olcObjectIdentifier: domainUserSchema 1.3.6.1.4.1.99999
olcObjectIdentifier: domainUserAttrs domainUserSchema:3
olcObjectIdentifier: domainUserOCs domainUserSchema:4
olcAttributeTypes: ( domainUserAttrs:1 NAME 'gender' DESC 'Gender of the person' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( domainUserAttrs:2 NAME 'userAccountControl' DESC 'Account control settings for the user' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )
olcAttributeTypes: ( domainUserAttrs:3 NAME 'userStatus' DESC 'Status settings for the user' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( domainUserAttrs:4 NAME 'userStatusValidFrom' DESC 'Status settings for the user' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )
olcAttributeTypes: ( domainUserAttrs:5 NAME 'employeeID' DESC 'Unique EmployeeID for the user' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: ( 1.3.6.1.4.1.4203.666.1.90 NAME 'accountExpires' DESC 'Account expiration time in 100-nanosecond intervals since January 1, 1601 (UTC)' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
olcAttributeTypes: ( domainUserAttrs:7 NAME 'pwdLastSet' DESC 'Password last changed in generalized time format' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE )
olcObjectClasses: ( domainUserOCs:1 NAME 'domainAccount' DESC 'User Identity in the organization' SUP top STRUCTURAL MUST ( cn $ sn $ uid $ employeeID $ gender $ userAccountControl $ userStatus $ userStatusValidFrom ) MAY ( sshPublicKey $ audio $ host $ pwdLastSet $ businessCategory $ carLicense $ departmentNumber $ description $ destinationIndicator $ displayName $ accountExpires $ employeeID $ employeeType $ facsimileTelephoneNumber $ gecos $ gidNumber $ givenName $ homeDirectory $ homePhone $ homePostalAddress $ initials $ internationaliSDNNumber $ jpegPhoto $ l $ labeledURI $ loginShell $ mail $ manager $ mobile $ o $ ou $ pager $ photo $ physicalDeliveryOfficeName $ postalAddress $ postalCode $ postOfficeBox $ preferredDeliveryMethod $ preferredLanguage $ registeredAddress $ roomNumber $ secretary $ seeAlso $ shadowExpire $ shadowInactive $ shadowLastChange $ shadowMax $ shadowMin $ shadowWarning $ st $ street $ telephoneNumber $ teletexTerminalIdentifier $ telexNumber $ title $ uidNumber $ userCertificate $ userPassword $ userPKCS12 $ userSMIMECertificate $ x121Address $ x500uniqueIdentifier ) )

dn: cn=automountSchema,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: automountSchema
olcObjectIdentifier: automountSchema 1.3.6.1.4.1.2312
olcAttributeTypes: ( 1.3.6.1.4.1.2312.4.1.2 NAME 'automountInformation' DESC 'Information used by the autofs automounter' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )
olcObjectClasses: ( 1.3.6.1.4.1.2312.4.2.3 NAME 'automount' SUP top STRUCTURAL DESC 'An entry in an automounter map' MUST ( cn $ automountInformation $ objectclass ) MAY ( description ) )
olcObjectClasses: ( 1.3.6.1.4.1.2312.4.2.2 NAME 'automountMap' SUP top STRUCTURAL DESC 'A group of related automount objects' MUST ( ou ) )

dn: cn=sudo,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: sudo
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.1 NAME 'sudoUser' DESC 'User(s) who may  run sudo' EQUALITY caseExactIA5Match SUBSTR caseExactIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.2 NAME 'sudoHost' DESC 'Host(s) who may run sudo' EQUALITY caseExactIA5Match SUBSTR caseExactIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.3 NAME 'sudoCommand' DESC 'Command(s) to be executed by sudo' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.4 NAME 'sudoRunAs' DESC 'User(s) impersonated by sudo (deprecated)' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.5 NAME 'sudoOption' DESC 'Options(s) followed by sudo' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.6 NAME 'sudoRunAsUser' DESC 'User(s) impersonated by sudo' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.7 NAME 'sudoRunAsGroup' DESC 'Group(s) impersonated by sudo' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcObjectClasses: ( 1.3.6.1.4.1.15953.9.2.1 NAME 'sudoRole' SUP top STRUCTURAL DESC 'Sudoer Entries' MUST ( cn ) MAY ( sudoUser $ sudoHost $ sudoCommand $ sudoRunAs $ sudoRunAsUser $ sudoRunAsGroup $ sudoOption $ description ) )
EOF

# Add the custom schema to the LDAP server
echo "Adding custom schema to LDAP server..."
sudo ldapadd -Y EXTERNAL -H ldapi:/// -f /tmp/customSchema.ldif

echo "Custom schema added successfully."

mkdir /var/lib/ldap/accesslog
chown openldap:openldap /var/lib/ldap/accesslog

# Modify the access rules
echo "Modifying LDAP access rules..."
cat <<EOF > /tmp/modifyAccess.ldif
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * filter=(userAccountControl=2) by * none
olcAccess: {1}to * by dn.exact="cn=admin,$BASE_DN" manage by dn="uid=ldapbinduser,ou=Users,$BASE_DN" read by * break
olcAccess: {2}to attrs=entry,uid by anonymous auth by * break
olcAccess: {3}to dn.subtree="$BASE_DN" by self read

dn: cn=config
changetype: modify
replace: olcAuthzRegexp
olcAuthzRegexp: {0}"uid=([^,]+),cn=gssapi,cn=auth" "ldap:///${BASE_DN}??sub?(&(uid=\$1))"

dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: constraint.la

dn: olcOverlay=constraint,olcDatabase={1}mdb,cn=config
changetype: add
objectClass: olcOverlayConfig
objectClass: olcConstraintConfig
olcOverlay: constraint
olcConstraintAttribute: userAccountControl regex ^(2|512)$
olcConstraintAttribute: groupType regex ^(-2147483646|-2147483644|-2147483640|2|4|8)$


dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: dynlist.la

dn: olcOverlay=dynlist,olcDatabase={1}mdb,cn=config
changetype: add
objectClass: olcDynamicList
objectClass: olcOverlayConfig
olcOverlay: dynlist
olcDlAttrSet: customGroup memberURL member+dgMemberOf

dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: unique.la

dn: olcOverlay=unique,olcDatabase={1}mdb,cn=config
changetype: add
objectClass: olcOverlayConfig
objectClass: olcUniqueConfig
olcOverlay: unique
olcUniqueAttribute: employeeID 
olcUniqueAttribute: ouID
olcUniqueAttribute: uniqueGroupID

dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: auditlog.la

dn: olcOverlay=auditlog,olcDatabase={1}mdb,cn=config
changetype: add
objectClass: olcOverlayConfig
objectClass: olcAuditLogConfig
olcOverlay: auditlog
olcAuditlogFile: /var/log/openldap/auditlog.log

dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: memberof.la

dn: olcOverlay=memberof,olcDatabase={1}mdb,cn=config
changetype: add
objectClass: olcConfig
objectClass: olcMemberOfConfig
objectClass: olcOverlayConfig
objectClass: top
olcOverlay: memberof
olcMemberOfDangling: ignore
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: customGroup
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf

dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: accesslog.la

dn: olcDatabase={2}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: mdb
olcDbDirectory: /var/lib/ldap/accesslog
olcSuffix: cn=accesslog
olcRootDN: cn=admin,cn=accesslog
olcRootPW: auditor_password
olcDbIndex: default eq
olcDbIndex: entryCSN,objectClass,reqEnd,reqResult,reqStart

dn: olcOverlay=accesslog,olcDatabase={1}mdb,cn=config
changetype: add
objectClass: olcOverlayConfig
objectClass: olcAccessLogConfig
olcOverlay: accesslog
olcAccessLogDB: cn=accesslog
olcAccessLogOps: all 
olcAccessLogSuccess: FALSE
olcAccessLogOld: cn=accesslog,$BASE_DN
olcAccessLogPurge: 1+00:00 01:00
EOF


sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/modifyAccess.ldif

echo "Adding user testuser123 to LDAP..."
cat <<EOF > /tmp/addUser.ldif
dn: ou=Domain Users,$BASE_DN
objectClass: organizationalUnit
objectClass: top
objectClass: customOU
ou: Domain Users
ouID: 1
ouParentID: 0

dn: ou=Users,$BASE_DN
objectClass: organizationalUnit
objectClass: top
objectClass: customOU
ou: Users
ouID: 5
ouParentID: 0

dn: ou=Groups,$BASE_DN
objectClass: organizationalUnit
objectClass: top
objectClass: customOU
ou: Groups
ouID: 2
ouParentID: 0

dn: cn=123,ou=Groups,$BASE_DN
objectClass: customGroup
objectClass: top
cn: 123
groupType: 2
uniqueGroupID: dd
memberURL: ldap:///ou=Domain Users,$BASE_DN??sub?(objectClass=domainAccount)

dn: cn=testuser123,ou=Domain Users,$BASE_DN
objectClass: domainAccount
objectClass: top
cn: testuser123
employeeID: 12345
gender: M
sn: User
uid: testuser123
userAccountControl: 512
userStatus: active
userStatusValidFrom: 20240721100000Z
uidNumber: 1001
gidNumber: 1002

dn: cn=testuser1233,ou=Domain Users,$BASE_DN
objectClass: domainAccount
objectClass: top
cn: testuser1233
employeeID: 12345456
gender: M
sn: User
uid: testuser1234
userAccountControl: 512
userStatus: active
userStatusValidFrom: 20240721100000Z
uidNumber: 1002
gidNumber: 1002

dn: ou=sudo,$BASE_DN
objectClass: customOU
objectClass: organizationalUnit
objectClass: top
ou: sudo
ouID: 4
ouParentID: 0

dn: cn=defaults,ou=sudo,$BASE_DN
objectClass: sudoRole
objectClass: top
cn: defaults
sudoOption: env_reset
sudoOption: mail_badpass
sudoOption: secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/s
 bin:/bin:/snap/bin

dn: cn=testuser123,cn=defaults,ou=sudo,$BASE_DN
objectClass: sudoRole
objectClass: top
cn: testuser123
sudoCommand: ALL
sudoHost: ALL
sudoRunAsUser: ALL
sudoUser: testuser123


dn: uid=ldapbinduser,ou=Users,$BASE_DN
objectClass: domainAccount
objectClass: top
cn: bind User
employeeID: 123454
gender: M
sn: User
uid: ldapbinduser
userAccountControl: 512
userStatus: active
userStatusValidFrom: 20240721100000Z

dn: ou=automount,$BASE_DN
objectClass: customOU
objectClass: organizationalUnit
objectClass: top
ou: automount
ouID: 3
ouParentID: 0

dn: ou=auto_home,ou=automount,$BASE_DN
objectClass: automountMap
objectClass: top
ou: auto_home

dn: ou=auto.master,ou=automount,$BASE_DN
objectClass: automountMap
objectClass: top
ou: auto.master

dn: ou=auto_master,ou=automount,$BASE_DN
objectClass: automountMap
objectClass: top
ou: auto_master

dn: cn=123,ou=auto_home,ou=automount,$BASE_DN
objectClass: automount
objectClass: top
automountInformation: -fstype=smbfs ://$AD_DOMAIN/Shared
cn: 123

dn: cn=321,ou=auto_home,ou=automount,$BASE_DN
objectClass: automount
objectClass: top
automountInformation: -fstype=smbfs ://$AD_DOMAIN/NotShared
cn: 321

dn: ou=auto.test,ou=auto.master,ou=automount,$BASE_DN
objectClass: automountMap
objectClass: top
ou: auto.test

dn: cn=/test,ou=auto.test,ou=auto.master,ou=automount,$BASE_DN
objectClass: automount
objectClass: top
automountInformation: auto.test
cn: /test

dn: cn=/shares,ou=auto.test,ou=auto.master,ou=automount,$BASE_DN
objectClass: automount
objectClass: top
automountInformation: auto.test
cn: /shares

dn: cn=home,cn=/test,ou=auto.test,ou=auto.master,ou=automount,$BASE_DN
objectClass: automount
objectClass: top
automountInformation: -fstype=cifs,rw,noperm,cruid=$UID,sec=krb5i       ://$AD_DOMAIN/HomeFolders
cn: home

dn: cn=pub,cn=/shares,ou=auto.test,ou=auto.master,ou=automount,$BASE_DN
objectClass: automount
objectClass: top
automountInformation: -fstype=cifs,rw,noperm,cruid=$UID,sec=krb5i       ://$AD_DOMAIN/Shared
cn: pub

dn: cn=notshared,cn=/shares,ou=auto.test,ou=auto.master,ou=automount,$BASE_DN
objectClass: automount
objectClass: top
automountInformation: -fstype=cifs,rw,noperm,cruid=$UID,sec=krb5i       ://$AD_DOMAIN/NotShared
cn: notshared

dn: cn=/test,ou=auto_master,ou=automount,$BASE_DN
objectClass: automount
objectClass: top
automountInformation: auto_home
cn: /test
EOF



ldapadd -x -D "cn=admin,$BASE_DN" -w $LDAP_ADMIN_PASS -f /tmp/addUser.ldif

# Retrieve Kerberos ticket



echo "Retrieving Kerberos ticket for $LDAP_DOMAIN..."
# Function to retrieve Kerberos ticket using expect
retrieve_ticket() {
  expect <<EOF
    spawn sudo ktutil -k /etc/ldap/ldap.keytab get -p $ADMIN_PRINCIPAL -e $ENCRYPTION_TYPE ldap/$LDAP_DOMAIN
    expect "Password for $ADMIN_PRINCIPAL@REALM:"
    send "$KRB_PASSWORD\r"
    expect eof
EOF
}
retrieve_ticket
# Change ownership and permissions of keytab file after ticket is retrieved
echo "Changing ownership and permissions of keytab file..."


sudo chmod 640 /etc/ldap/ldap.keytab
sudo chown openldap:openldap /etc/ldap/ldap.keytab 

echo "Configuring SASL in slapd.conf..."

sudo tee /usr/lib/sasl2/slapd.conf <<EOF
mech_list: gssapi digest-md5 cram-md5 external
keytab: /etc/ldap/ldap.keytab 
EOF

echo "Kerberos ticket retrieved successfully."
sudo systemctl restart slapd



if ! grep -q "^SASL_MECH GSSAPI" /etc/ldap/ldap.conf; then
    echo "Adding SASL_MECH GSSAPI to /etc/ldap/ldap.conf..."
    sudo awk '1; END { print "SASL_MECH GSSAPI" }' /etc/ldap/ldap.conf > /etc/ldap/ldap.conf.new
    sudo mv /etc/ldap/ldap.conf.new /etc/ldap/ldap.conf
fi

if ! grep -q "^SASL_REALM KRB" /etc/ldap/ldap.conf; then
    echo "Adding SASL_REALM KRB to /etc/ldap/ldap.conf..."
    sudo awk '1; END { print "SASL_REALM KRB" }' /etc/ldap/ldap.conf > /etc/ldap/ldap.conf.new
    sudo mv /etc/ldap/ldap.conf.new /etc/ldap/ldap.conf
fi

echo "LDAP server installation and configuration completed successfully."

sudo systemctl restart slapd

echo "Checking Mechanisms..."
ldapsearch -x -H ldapi:/// -b "" -LLL -s base supportedSASLMechanisms

echo "Setting Hostname to $LDAP_DOMAIN"
sudo hostnamectl set-hostname $LDAP_DOMAIN 

echo "Restart needed for changes to take full effect" 


cat <<EOF > ou-sync.yaml
source:
  server_uri: 'ldap://$LDAP_DOMAIN:389'
  bind_dn: 'cn=admin,$BASE_DN'
  bind_password: 'Abc1234'
  search_base: "$BASE_DN"
target:
  server_uri: 'ldap://$AD_DOMAIN:389'
  bind_dn: 'CN=Administrator,CN=Users,$AD_BASE_DN'
  bind_password: 'Abc1234'
  search_base: "$AD_BASE_DN"
EOF

#### Python script sync-ous.py can be used with these credentials 

## Missing: Host keytab 