This vulnerability occurs in environments using Windows Server 2022 with Heimdal Kerberos and a two-way cross-realm trust setup. When a user mapping in Active Directory (AD) is removed and then re-added, subsequent attempts to mount a CIFS  share on a Linux Client by a user from an external Heimdal Kerberos realm can cause an Input/Output (I/O) error on the client side and force a restart of the Domain Controller (DC).

It takes a minute until the restart is executed the DC. If the client computer isn't restarted, the Windows Server can be shutdown indefinitely. If the attack is executed while no user is logged into the Windows Server, the User will not be able to log onto the Windows Server. The DC/File server will be able to run for a minute or two, after the client gets a few "Permission Denied" errors, the exploit will be successful again. *This results in a persistent DoS.*

The environment was built in VirtualBox. The Client is an Ubuntu Desktop 24.04 LTS, and the Heimdal Server is an Ubuntu Server 24.04 LTS. Additionally, there is an OpenLDAP server running, and I am using SSSD, but that should not be needed. 


Setting up a standard Heimdal Kerberos realm with a two-way realm trust to AD. It should be replicable on an unmodified Heimdal Server. Setting up a Linux Client that can authenticate against the Kerberos realm. The Domains will be KRB and KERBEROSAD.UNI-MAGDEBURG.DE. The mappings are created in the extended Advanced View in AD Users and Computers option: User - Name Mappings - Kerberos Names.

The KRB  user should now be able to receive the AD CIFS tickets if he tries to mount an AD CIFS. If a mapping to a user exists, e.g. testuser@KERBEROSAD.UNI-MAGDEBURG.DE and testuser@KRB, then the user will be able to mount and access the CIFS directory. 

For simplicity, use sudo "kinit testuser@KRB", then "sudo mount -a". "sudo mount -a" will execute the "fstab":
//kerberosad.kerberosad.uni-magdeburg.de/Shared /mnt/share cifs user=testuser,sec=krb5,uid=1001,gid=1001,cruid=root 0 0
//kerberosad.kerberosad.uni-magdeburg.de/NotShared /mnt/notshared cifs user=testuser,sec=krb5,uid=1001,gid=1001,cruid=root 0 0

"kerberosad.kerberosad.uni-magdeburg.de" is the DNS Name for the file server. The file server is also the Domaincontroller. I have not tried to set up a separate file server. The Shared Folder has to be on the main drive, C:/.

The above will work if Kerberos Realm user mapping exists for the client (Image 1).

The client /etc/krb5.conf on the client is standard, without providing any additional configuration except for the default_realm and realm setup. 


[libdefaults]
	default_realm = KRB

# The following krb5.conf variables are only for MIT Kerberos.
	kdc_timesync = 1
	ccache_type = 4
	forwardable = true
	proxiable = true
        rdns = false


# The following libdefaults parameters are only for Heimdal Kerberos.
	fcc-mit-ticketflags = true

[realms]
	KRB = {
		kdc = heimdal.krb.uni-magdeburg.de
		admin_server = heimdal.krb.uni-magdeburg.de
	}

[domain_realm]
	<empty here>

heimdal.krb.uni-magdeburg.de is the Heimdal KDC. It only has the trust principals:
    - krbtgt/KERBEROSAD.UNI-MAGDEBURG.DE@KRB
    - krbtgt/KRB@KERBEROSAD.UNI-MAGDEBURG.DE

and then a user Principal:
   -  testuser@KRB

The Heimdal KDC krb5.conf Configuration can be seen in Image 3. In Image 5 the trust Configuration of Windows is displayed. 


Now to execution. A local Linux User logs onto the client. Using kinit testuser@KRB, he obtains his ticket. The User Mapping exists; he uses sudo mount -a to mount the shares. In AD, remove the User Mapping. Reboot the Linux Client. Again, log onto the Linux client. Attempt mount-a; this will prompt "Permission Denied". Re-add the User Mapping on AD, try to mount the share, and the I/O Error will appear, restarting the File server/DC. This last step can then be executed indefinitely. 

The entire Environment can be seen in Image 2.


Simplified: 
- have a mapped user in AD <--> two-way cross-realm Kerberos
- Have an external Kerberos realm
- have a Client PC
- kinit <user> of External Realm on client PC
- try to mount share, file server --> Permission granted, works fine
- reboot the Linux Machine, log in
- remove the user mapping in AD
- kinit <user> of External Realm
- try to permission denied
- add user mapping


The Linux Client will tells me:
mount.cifs kernel mount options: ip=172.16.0.16,unc=\\kerberosad.kerberosad.uni-magdeburg.de\Shared,sec=krb5,uid=1001,cruid=0,gid=1001,user=testuser,pass=********
mount error(5): Input/output error
Refer to the mount.cifs(8) manual page (e.g. man mount.cifs) and kernel log messages (dmesg)
mount.cifs kernel mount options: ip=172.16.0.16,unc=\\kerberosad.kerberosad.uni-magdeburg.de\NotShared,sec=krb5,uid=1001,cruid=0,gid=1001,user=testuser,pass=********
mount error(5): Input/output error
Refer to the mount.cifs(8) manual page (e.g. man mount.cifs) and kernel log messages (dmesg)

The Windows Server tells me:
The DFS Replication service has detected an unexpected shutdown on volume C:. This can occur if the service terminated abnormally (due to a power loss, for example) or an error occurred on the volume. The service has automatically initiated a recovery process. The service will rebuild the database if it determines it cannot reliably recover. No user action is required. 
 
Additional Information: 
Volume: C: 
GUID: 4308749A-0000-0000-0000-500600000000

sudo kadmin -l
add -pw Abc1234 KERBEROSAD.UNI-MAGDEBURG.DE@KRB
add -pw Abc1234 KRB@ KERBEROSAD.UNI-MAGDEBURG.DE 
