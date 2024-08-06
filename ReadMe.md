

# OpenLDAP Sync Dokumentation
## Inhaltsverzeichnis

1. [Onboarding](#onboarding)
    1. [OpenLDAP und Active Directory](#openldap-und-active-directory)
        1. [OpenLDAP Installation](#openldap-installation)
        2. [Client Installation](#client-installation)
    2. [Integrierter Ansatz: Heimdal, OpenLDAP und AD](#integrierter-ansatz-heimdal-openldap-und-ad)
        1. [OpenLDAP Installation](#openldap-installation-1)
        2. [Kerberos Installation](#kerberos-installation)
        3. [Client Installation](#client-installation-1)
        4. [Ausfallsicherheit](#ausfallsicherheit)
        5. [PKINIT](#pkinit)
2. [Manuelle Installation von Kadmin Interface](#manuelle-installation-von-kadmin-interface)
    1. [Keytab](#keytab)
        1. [AD Keytab](#ad-keytab)
        2. [Heimdal Keytab](#heimdal-keytab)
    2. [Python Skript](#python-skript)
3. [Active Directory](#attribute-in-active-directory)
    3.1 [Attribute in Active Directory](#attribute-in-active-directory)
    3.2 [LDAPS Setup](#ldaps-setup)
4. [Synchronisation](#synchronisation)
    1. [Ausführen der Synchronisationsskripte](#ausführen-der-synchronisationsskripte)
5. [Kerberos mit OpenLDAP-Backend](#kerberos-mit-openldap-backend)
    1. [OpenLDAP](#openldap)
        1. [Heimdal Schema hinzufügen](#heimdal-schema-hinzufügen)
        2. [Einrichten der olcAccess-Richtlinie](#einrichten-der-olcaccess-richtlinie)
    2. [Heimdal KDC](#heimdal-kdc)
    3. [Probleme bei der Implementation](#probleme-bei-der-implementation)
    4. [Versuch Installation LDAP mit Heimdal durch Source](#versuch-installation-ldap-mit-heimdal-durch-source)

## Onboarding

Damit Maschinen einheitlich und einfach installiert werden können, wurden Onboarding-Skripts für verschiedene Instanzen erstellt. 
Diese Skripte können nur auf Linux ausgeführt werden. 

Ein Onboarding-Skript kann durch folgende Befehle ausgeführt werden:

Die DNS-Einträge müssen zuerst erstellt werden. Dafür kann SRV benutzt werden. Dabei sind die Skripte dafür jedoch nicht speziell erstellt. 



!!!
**Während dieses Dokument geschrieben wurde, ist der LSC-Server unerreichbar geworden..** 
!!!

Alternative Installation:
**Dateien aus lsc-install auf dem Server speichern**

```s
cat lsc_2.1.6-1_all.deb.part-* > lsc_2.1.6-1_all.deb
sudo dpkg -i lsc_2.1.6-1_all.deb
```

**Die DNS-Einträge müssen auf dem DNS-Server existieren**

**Der Ablauf sollte wie folgt aussehen:**

1. Auf dem Heimdal-Server das Skript für Heimdal ausführen.
2. Anschließend das OpenLDAP-Skript ausführen.
3. Beide Server neu starten.
4. Clients anbinden:
    - Das SSSD-Skript ausführen.


```s
chmod +x script.sh
./script.sh
```
### 4.1.2 OpenLDAP und Active Directory 

#### OpenLDAP Installation


Ein OpenLDAP Server kann durch das OpenLDAP Onboarding Skript aus [`onboarding/ldap-ad-auth`](onboarding/ldap-ad-auth/openldap.sh) installiert werden. 

#### Client Installation 
*Linux*

Auf Linux kann das Onboarding-Skript ausgeführt werden. Davor müssen die Einstellungen in diesem angepasst werden. 

Für macOS muss der Server unter Benutzer eingeschrieben werden. Dabei kann die IP-Adresse oder die DNS verwendet werden. Es muss die RFC-Option gewählt werden und der Suchbereich muss dabei angegeben werden.  Die Mappings müssen entsprechend angepasst werden. Unter Users muss domainAccount als Objektklasse hinzugefügt werden. Dann wird unter Sicherheit der LDAP-Bind-Nutzer mit dem Passwort angegeben. Der Nutzer muss als DN angegeben werden. 

*macOS*

Der SASL Mechansmus CRAM-MD5 muss deaktiviert werden durch. Dabei auf Mojave mit dem Skript:
```s
for m in CRAM-MD5; do /usr/libexec/PlistBuddy -c "add ':module options:ldap:Denied SASL Methods:' string $m" /Library/Preferences/OpenDirectory/Configurations/LDAPv3/<LDAP_DNS/IP>.plist
 done
```
und auf Sonoma mit dem Befehl:
```s
sudo odutil set configuration /LDAPv3/<LDAP_DNS/IP> module ldap option "Denied SASL Methods" CRAM-MD5 
```

*Windows*

Computer können standardmäßig an die AD-Domäne angeschlossen werden. Durch pGina können diese auch an OpenLDAP angeschlossen werden.

Dabei sollten Authentifikation und Gateway für lokale Maschinen und OpenLDAP aktiviert sein. Unter LDAP muss ein Bind-Nutzer angegeben werden, mit DN und Passwort. 
Unter Suchbereich werden die Suchbereiche festgelegt, dabei sollte die zweite Version aktiviert werden, mit %uid und Sucherbereich, wo die Nutzer abgelegt sind. 


### 4.1.3 Integrierter Ansatz: Heimdal, OpenLDAP und AD 

#### OpenLDAP Installation

Ein OpenLDAP Server kann durch das Onboarding Skript aus [`onboarding/cross-realm`](onboarding/cross-realm/openldap_vorgeschlagent.sh) installiert werden. *Vorgeschlagen ist dabei die getrennte Konfiguration von Nutzern und Gruppen* 


#### Kerberos Installation 
Ein Kerberos Server kann durch das Onboarding Skript aus[`onboarding/cross-realm`](onboarding/cross-realm/heimdal-kdc.sh) aus installiert werden. 

Das python Skript kann alle Python Funktionen automatisch erstellen. Es muss als Non-root-Nutzer durchgeführt werden. 

#### Client Installation 
*Linux*

Auf Linux kann das Onboarding-Skript ausgeführt werden. Davor müssen die Einstellungen in diesem angepasst werden. 

*macOS*

Für macOS muss der Server unter Benutzer eingeschrieben werden. Dabei kann die IP-Adresse oder die DNS verwendet werden. Es muss die RFC-Option gewählt werden und der Suchbereich muss dabei angegeben werden.  Die Mappings müssen entsprechend angepasst werden. Unter Users muss domainAccount als Objektklasse hinzugefügt werden. Dann wird unter Sicherheit der LDAP-Bind-Nutzer mit dem Passwort angegeben. Dieser muss nur als Benutzername angegeben werden und nicht als DN. 


*Windows*

Windows Geräte können nur an die Active Directory Domäne angebunden werden. Ein Beispiel der Gruppenrichtlinien ist unter GPO.html zu sehen.
Sonst wird der KDC durch folgende Befehle auf den Clients eingerichtet:
```s
ksetup /addkdc HEIMDAL.UNI-MAGDEBURG.DE $HEIMDAL_SERVER_DNS
ksetup /addhosttorealmmap <HOST-FQDN> HEIMDAL.UNI-MAGDEBURG.DE
ksetup /addhosttorealmmap $HEIMDAL_SERVER_DNS HEIMDAL.UNI-MAGDEBURG.DE
```
Für die Befehle werden Administrator-Rechte benötigt
#### Ausfallsicherheit

Die Ausfallsicherheit wurde nur für den Kerberos Realm getestet, da die Replikation beziehungsweise Synchronisation andersweitig erläutert wird. 
Auf dem Master-KDC müssen die `hprop` Service Principals in einer Keytab gespeichert werden. Auf einem weiteren Server wird das Onboarding-Skript `onboarding/cross-realm/replica-heimdal.sh` ausgeführt. Dies muss denselben Realm, wie der Master, haben. Daher müssen `heimdal-kdc.sh` und `replica-heimdal.sh` abgestimmt sein. 

```s
sudo kadmin -l add hprop/$REPLICA_FQDN@$REALM
sudo kadmin -l ext -k /etc/hprop.keytab kadmin/hprop@$REALM
sudo kadmin -l ext -k /etc/hprop.keytab hprop/$REPLICA_FQDN@$REALM
sudo hprop -k keytab $REPLICA_FQDN
```

Die Keytab `/etc/krb5.keytab`, die Datenbank, `/var/lib/heimdal-kdc/heimdal.db` und der Master-Schlüssel `/var/lib/heimdal-kdc/m-key` müssen in den gleichen Pfaden auf dem Slave installiert sein. 

In `/etc/heimdal-kdc/kdc.conf` müssen Port 88 und 754 geöffnet sein. Dies wird unter `[kdc]` festgelegt mit
```s
ports = 754, 88, 464 
```  

`krb_prop` muss unter /etc/inetd.conf einkommentiert werden. 

Port 88 dient zur Kerberos Authentifikation und Port 754 für die Propagation der Daten durch hprop. 

Dann kann durch einen Befehl auf dem Master die Propagation initalisiert werden.
```s
hprop -k /etc/hprop.keytab $REPLICA_FQDN
```

Der Hostname des Replica muss mit dem DNS-Eintrag übereinstimmen. 
#### PKINIT
Die PKINIT-Funktionen werden mit den Skripten mitgeliefert. 

Es kann durch den folgenden Befehl getestet werden:
```s
kinit -C FILE:user.pem,user.key <UserInCert>
```

## Manuelle Installation von Kadmin Interface

### Keytab

#### AD Keytab

- Konfiguration in Konfigurationsdateien tätigen
  - Es muss die keytabs geben.
  - Der Nutzer des Service Tickets für Passwortänderungen braucht administrative Rechte, diese beschränken sich auf Passwortänderungen.
  - für Active Directory wird nur dann ein Keytab benötigt, wenn dort auch Änderungen passieren sollen. 

**HOWTO AD:**

```shell
setspn -A script/heimdalserver.heimdal.uni-magdeburg.de svc_passchange
ktpass -princ script/heimdalserver.heimdal.uni-magdeburg.de@KERBEROS.UNI-MAGDEBURG.DE -mapuser svc_passchange@KERBEROS.UNI-MAGDEBURG.DE -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -pass Abc1234 -out svc_passchange.keytab
```

**HOWTO HEIMDAL:**

```shell
sudo -p admin/admin kadmin ext -k admin.keytab admin/admin
sudo chown <currentuser>: admin.keytab
```

### Python Skript
Python Onboarding Skript ausführen
/onboarding/cross-realm/python_script.sh

in die Ordner kadmin und kerberosservice die nötigen Dateien

kadmin:
    - setup.py
    - kadmin_interface_wrapper.c
kerberosservice:
    - setup.py
    - kerberosservice.c
py:
    - main.py
    - ldap_monitor.py
    - kerberos_principal.py
    - enum_change_type.py
    - admin.keytab (so, wie in server-config.yaml festgelegt)
installieren.

source /<env>/bin/activate


Dahin navigieren, wo gespeichert die jeweiligen setup.py mit C-Bibliothek Dateien gespeichert sind:

    1. pip setup.py build
    2. pip install .
    3. Danach kann main.py benutzt werden
    4. Einrichten der Konfigurationsdateien (ad-server.yaml, server-config.yaml)
    5. python3 main.py

Zu beachten ist, dass der Nutzer die Notwendigen Rechte auf venv und andere Ordner hat. Das Skript python_script.sh soll hier ohne sudo ausgeführt werden.  
## Active Directory
### Attribute in Active Directory
Um die Schemata verändern zu können, muss ein Adminaccount `regsvr32 schmmgmt.dll` ausführen.

Damit die Synchronisation vollständig funktionieren kann, müssen die Attribute in Active Directory erstellt werden. Diese muss den Objektklassen zugeordnet werden.
- Nutzer (objectClass: user)
    - userStatus
        - Unicode String
        - Random OID
    - userStatusValidFrom
        - generalizedTime
        - Random OID
    - gender
        - Unicode String
        - Random OID
- Organsiationseinheit (objectClass: organizationalUnit)
    - ouID
        - Unicode String
        - Random OID
    - ouParentID
        - Unicode String
        - Random OID
- Gruppe (objectClass: group)
    - uniqueGroupID
        - Unicode String
        - Random OID
Dann entweder den Active Directory Domain Service Dienst neustarten oder den Server neustarten. 

#### LDAPS Setup
Rolle: AD Certificate Authority
- Certificate Authority 
    
    1. Certificate Authority    
    2. Enterprise Option
    3. Root option
    4. Create new PK Option
    5. SHA512-Hash
    6. keeping CA name
- Neustart

Folgend auf Linux:

```s
openssl s_client -connect $AD_DOMAIN:636 -showcerts < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ad_cert.pem

cp ad_cert.pem /usr/local/share/ca-certificates/ad_cert.crt

update-ca-certificates
```

## Synchronisation 
Für die Synchronisation wird LSC-Projekt verwendet. https://lsc-project.org/ Alternativ: https://lsc.readthedocs.io/en/latest/index.html

### Ausführen der Synchronisationsskripte

- Erstellen der Nutzer durch create.py 
dann kann:

```
sudo lsc -s all
    - einfache Synchronisation
sudo lsc -c all
    - entfernen überflüssiger Einträge
sudo lsc -a all
    - Asynchrone / Ereignissbasierte Synchronisation 
```

verwendet werden. Davor sollte *sync_ou.py* ausgeführt werden, damit die Organisationeinheiten korrekt synchronisiert sind. Dafür gibt es eine Konfigurationsdatei, welche angepasst werden muss.  


## Kerberos mit OpenLDAP-Backend
übernommen von: https://wiki.crans.org/WikiNit/Notes/LdapKerberos und https://github.com/heimdal/heimdal/blob/master/doc/setup.texi

### OpenLDAP
OpenLDAP Konfiguration kann von Onboarding Skripten übernommen werden.

Damit Principals hinzugefügt werden können, muss das kerberos schema aus ldap/full_schema installiert werden. 

#### Heimdal Schema hinzufügen
Heimdal muss durch heimdal-kdc auf der selben Instanz installiert werden. 
0. sudo apt-get install slapd 
1. mkdir /tmp/ldif
2. erstellen von Konfigurationsdatei zum erstellen dynamischer Konfiguration, /tmp/schema.conf
``` 
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/hdb.schema
```
3. slapcat -f /tmp/schema.conf -F /tmp/ldif -n0 -s "cn={1}hdb,cn=schema,cn=config"  | sed 's/{1}hdb/hdb/' | grep '^\(dn:\|objectClass:\|cn:\|olc\| \)' > /tmp/hdb.ldif
4. ldapadd -Y EXTERNAL -H ldapi:/// -f /tmp/hdb.ldif



#### Einrichten der olcAccess-Richtlinie
Der Adminaccount External Account muss Zugriffsrechte haben. Dies sollte anders implementiert werden, aber zum testen funktioniert das folgende: 
```s
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.exact=gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth manage by * break
```

### Heimdal KDC

unter /etc/heimdal-kdc/kdc.conf
```s
[kdc]
database = {
  dbname = ldap:ou=container,$BASE_DN 
  acl_file = /etc/heimdal-kdc/kadmind.acl
  mkey_file = /var/lib/heimdal-kdc/m-key
}
   
hdb-ldap-structural-object = account 
```
Das Standard LDAP Objekt was erstellt wird ist account. Es kann auch inetOrgPerson oder domainAccount gewählt werden.


Erstellen von OU für Princiapls container
```s
sudo kadmin -l init $REALM
```


Die Kerberos Principals sollten jetzt in OpenLDAP sichtbar sein. 

### Probleme bei der Implementation

1. Die Principals scheinen in Kerberos erstellt werden zu müssen. Es war mit der Konfiguration nicht möglich, Principals nachträglich für Nutzer zu erstellen.
2. Es konnte nur die Objektklasse `account` verwendet werden, da andere Attribute, wie sn oder cn nicht automatisch erstellt werden. 

### Versuch Installation LDAP mit Heimdal durch Source
0. wget http://archive.ubuntu.com/ubuntu/pool/main/h/heimdal/heimdal_7.7.0+dfsg.orig.tar.xz 
0.5. tar -xf heimdal_7.7.0+dfsg.orig.tar.xz
1. sudo apt-get install build-essential libncurses5-dev libncursesw5-dev libdb-dev heimdal-dev autoconf automake libtool flex bison pkg-config texinfo
2. sudo ./configure --with-openldap=/usr
3. sudo make 
4. sudo make install 


