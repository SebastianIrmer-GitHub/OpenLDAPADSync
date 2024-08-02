# PKINIT 
```
hxtool issue-certificate --self-signed --issue-ca --generate-key=rsa --subject="CN=CA,DC=krb,DC=uni-magdeburg,DC=de" --lifetime=10years --certificate="FILE:ca.pem"

hxtool issue-certificate --ca-certificate=FILE:ca.pem --generate-key=rsa --type="pkinit-kdc" --pk-init-principal="krbtgt/KRB@KRB" --subject="uid=heimdal,DC=krb,DC=uni-magdeburg,DC=de" --certificate="FILE:kdc.pem"

hxtool issue-certificate --ca-certificate=FILE:ca.pem --generate-key=rsa --type="pkinit-client" --pk-init-principal="testuser123@KRB" --subject="uid=testuser123,DC=krb,DC=uni-magdeburg,DC=de" --certificate="FILE:user.pem"
```
### unter /etc/heimdal-kdc/kdc.conf unter [kdc]:
```
...
enable-pkinit = yes
pkinit_identity = FILE:/etc/heimdal-kdc/pkinit/kdc.pem
pkinit_anchors = FILE:/etc/heimdal-kdc/pkinit/ca.pem
pkinit_allow_proxy_certificate = false
pkinit_win2k_require_binding = yes
...
```

###  unter /etc/krb5.conf
```
[libdefaults]
pkinit_anchors = FILE:/etc/ssl/certs/ca.pem
...
```
### CA 
```
openssl pkey -in ca.pem -out ca.key

openssl x509 -in ca.pem -out ca.pem.new
mv ca.pem.new ca.pem
```

###  User
```
openssl pkey -in ca.pem -out ca.key

openssl x509 -in user.pem -out user.pem.new
mv user.pem.new user.pem
```

###  Testing:
```
kinit  -C FILE:user.pem,user.key testuser123@KRB
```

#### 
Standardmäßig erstellen die Onboarding Skripte bereits diese Daten
- dadurch kann der folgende Befehl nach Installation verwendet werden. 
```
kinit  -C FILE:user.pem,user.key testuser123@KRB
```
