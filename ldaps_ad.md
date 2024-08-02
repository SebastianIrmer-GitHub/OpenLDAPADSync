

#### LDAPS 
Role: AD Certificate Authority
- Certificate Authority 
    - configure:
        - CA    
        - Enterprise
        - Root
        - Create new PK
        - SHA512-Hash
        - keeping CA name
- reboot

on Linux:
openssl s_client -connect AD100.kerberos.uni-magdeburg.de:636 -showcerts < /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ad_cert_chain.pem