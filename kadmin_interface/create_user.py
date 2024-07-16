import kadmin 
import kerberosservice

def change_password(user, realm, keytab_file, new_password):
    try:
        # Changing password in the specified realm
        kerberosservice.change_password_keytab(user, realm, keytab_file, new_password)
        print(f"Password for {user} in realm {realm} has been successfully changed.")
    except Exception as e:
        print(f"Failed to change password for {user} in realm {realm}. Error: {e}")

def add_principal_to_kerberos(username, password):
    try:
        kadmin.add_principal(username, password)
        print(f"Principal {username} added to Kerberos.")
    except RuntimeError as e:
        print(f"Error adding principal {username}: {e}")

if __name__ == "__main__":
    with open('server-config.yaml', 'r') as config_file:
        config = yaml.safe_load(config_file)

    ldap_config = config['ldap']

    ldap_server = ldap_config['server']
    ldap_user = ldap_config['user']
    ldap_password = ldap_config['password']
    ldap_search_base = ldap_config['search_base']
    ldap_search_filter = ldap_config['search_filter']
    ldap_attributes = ldap_config['attributes']

    change_password(user, realm_kerberosad, keytab_kerberosad, new_password)
    add_principal_to_kerberos(user, new_password)
    
    kerberosservice.change_password_old("testuser123@KRB", "Abc12346", "Abc1234")
