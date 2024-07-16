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

def add_principal_to_kerberos(username, password):
    try:
        kadmin.add_principal(username, password)
        print(f"Principal {username} added to Kerberos.")
    except RuntimeError as e:
        print(f"Error adding principal {username}: {e}")

def main():
    ldap_usernames = set()

    # Retrieve all users from LDAP
    conn.search(search_base=ldap_search_base, search_filter=ldap_search_filter, search_scope=SUBTREE, attributes=ldap_attributes)
    for entry in conn.entries:
        uid = entry.uid.value
        ldap_usernames.add(uid)

    kerberos_principals = print_principals()
    kerberos_usernames = set(get_username(principal) for principal in kerberos_principals)

    for username in ldap_usernames:
        if username not in kerberos_usernames:
            print(f"User {username} not found in Kerberos. Adding...")
            add_principal_to_kerberos(username, 'Abc1234')
        else:
            print(f"User {username} already exists in Kerberos.")

    # Unbind the LDAP connection
    conn.unbind()

if __name__ == "__main__":
    main()
