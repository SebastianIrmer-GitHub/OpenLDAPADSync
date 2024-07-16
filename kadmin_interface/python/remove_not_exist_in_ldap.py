import kadmin
from ldap3 import Server, Connection, ALL, SUBTREE
import yaml

# Load the LDAP configuration from the YAML file
with open('server-config.yaml', 'r') as config_file:
    config = yaml.safe_load(config_file)

ldap_config = config['ldap']

ldap_server = ldap_config['server']
ldap_user = ldap_config['user']
ldap_password = ldap_config['password']
ldap_search_base = ldap_config['search_base']
ldap_search_filter = ldap_config['search_filter']
ldap_attributes = ldap_config['attributes']

# Connect to the LDAP server
server = Server(ldap_server, get_info=ALL)
conn = Connection(server, user=ldap_user, password=ldap_password, auto_bind=True)

def get_username(principal):
    return principal.split('@')[0]

def print_principals():
    try:
        principals = kadmin.list_principals()
        return principals
    except RuntimeError as e:
        print(f"Error: {e}")
        return []

def check_principal_in_ldap(username):
    search_filter = f"(uid={username})"
    conn.search(search_base=ldap_search_base, search_filter=search_filter, search_scope=SUBTREE, attributes=ldap_attributes)
    return conn.entries

if __name__ == "__main__":
    principals = print_principals()

    for principal in principals:
       
        username = get_username(principal)
        if "/" in username:
            continue
        
        if "admin" in username or "default" in username:
            continue
        
        print(f"Checking principal information for user: {username}")

        ldap_entries = check_principal_in_ldap(username)
        if ldap_entries:
            for ldap_entry in ldap_entries:
                print(f"Found LDAP entry for {username}: {ldap_entry}")
        else:
            print(f"No LDAP entry found for {username}")
            kadmin.delete_principal(principal)

    conn.unbind()
