import traceback
from ldap3 import Server, Connection, ALL, SUBTREE
import yaml

# Load configuration from the YAML file
with open('ou-sync.yaml', 'r') as file:
    config = yaml.safe_load(file)

# Extract source and target configurations
source_config = config['source']
target_config = config['target']

def get_all_ous(config):
    """
    Retrieve all organizational units (OUs) from an LDAP server.

    :param config: Dictionary containing server URI, bind DN, bind password, and search base
    :return: List of tuples containing OU name, distinguished name, ouID, and ouParentID
    """
    server = Server(config['server_uri'], get_info=ALL)
    ous = []
    try:
        with Connection(server, config['bind_dn'], config['bind_password'], auto_bind=True) as conn:
            search_base = f"{config['search_base']}"
            search_filter = '(objectClass=customOU)'
            attributes = ['ou', 'ouID', 'ouParentID', 'distinguishedName']

            if conn.search(search_base, search_filter, attributes=attributes, search_scope=SUBTREE):
                for entry in conn.entries:
                    ou_name = entry.ou.value if entry.ou else "Unknown OU"
                    dn = entry.entry_dn
                    ou_id = entry.ouID.value if entry.ouID else None
                    ou_parent_id = entry.ouParentID.value if entry.ouParentID else None
                    ous.append((ou_name, dn, ou_id, ou_parent_id))
            else:
                print("No entries found.")
    except Exception as e:
        print("LDAP error during OU retrieval:", str(e))

    return ous

def get_all_target_ous(config):
    """
    Retrieve all OUs from the target LDAP server.

    :param config: Dictionary containing server URI, bind DN, bind password, and search base
    :return: List of distinguished names of OUs
    """
    server = Server(config['server_uri'], get_info=ALL)
    ous = []
    try:
        with Connection(server, config['bind_dn'], config['bind_password'], auto_bind=True) as conn:
            search_base = config['search_base']
            search_filter = '(objectClass=organizationalUnit)'
            attributes = ['distinguishedName']

            if conn.search(search_base, search_filter, attributes=attributes, search_scope=SUBTREE):
                for entry in conn.entries:
                    dn = entry.entry_dn
                    ous.append(dn)
            else:
                print("No entries found.")
    except Exception as e:
        print("LDAP error during target OU retrieval:", str(e))

    return ous

def move_ou(config, old_dn, new_dn, ou_name):
    """
    Move an OU to a new distinguished name.

    :param config: Dictionary containing server URI, bind DN, bind password
    :param old_dn: Current distinguished name of the OU
    :param new_dn: New distinguished name for the OU
    :param ou_name: Name of the OU
    """
    server = Server(config['server_uri'], get_info=ALL)
    ou_name = f"ou={ou_name}"
    new_dn = new_dn.replace(f"{ou_name},", "")
    try:
        with Connection(server, config['bind_dn'], config['bind_password'], auto_bind=True) as conn:
            if conn.modify_dn(old_dn, ou_name, new_superior=new_dn):
                pass
            else:
                pass
    except Exception as e:
        print("LDAP error during OU move:", str(e))

def convert_specific_parts_to_lowercase(dn):
    """
    Convert only the CN=, DC=, and OU= parts of a distinguished name (DN) to lowercase.

    :param dn: Distinguished name to convert
    :return: DN with specified parts converted to lowercase
    """
    parts = dn.split(',')
    lowercase_parts = []
    for part in parts:
        if part.strip().startswith('CN='):
            lowercase_parts.append('cn=' + part[3:])
        elif part.strip().startswith('DC='):
            lowercase_parts.append('dc=' + part[3:])
        elif part.strip().startswith('OU='):
            lowercase_parts.append('ou=' + part[3:])
        else:
            lowercase_parts.append(part)
    return ','.join(lowercase_parts)

def ou_exist_under_base(config, base_dn, ou_id):
    """
    Check if an OU exists under a specific base DN.

    :param config: Dictionary containing server URI, bind DN, bind password
    :param base_dn: Base distinguished name to search under
    :param ou_id: ID of the OU to check for
    :return: Tuple containing a boolean indicating existence and the DN if it exists
    """
    server = Server(config['server_uri'], get_info=ALL)
    try:
        with Connection(server, config['bind_dn'], config['bind_password'], auto_bind=True) as conn:
            search_filter = f'(&(objectClass=organizationalUnit)(orgUnitID={ou_id}))'
            conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE)
            
            if len(conn.entries) > 0:

                return True, conn.entries[0].entry_dn
            else:
                return False, None
    except Exception as e:
        print("LDAP error during OU existence check:", str(e))
        return False, None

def create_ou_if_not_exists(config, ou_name, distinguished_name, ou_id, ou_parent_id):
    """
    Create an OU in the target LDAP server if it does not already exist.

    :param config: Dictionary containing server URI, bind DN, bind password, and search base
    :param ou_name: Name of the OU to create
    :param distinguished_name: Distinguished name of the OU in the source LDAP
    """
    server = Server(config['server_uri'], get_info=ALL)
    target_base = config['search_base']
    new_target_dn = distinguished_name.replace(source_config['search_base'], target_base)
    base_dn = f"{target_base}"
    new_target_dn = convert_specific_parts_to_lowercase(new_target_dn)
    try:
        with (Connection(server, config['bind_dn'], config['bind_password'], auto_bind=True) as conn):
            if ou_name == "sudo" or ou_name == "automount" or ou_name == "Users": 
                return
            
            ou_exists, existing_target_dn = ou_exist_under_base(config, base_dn, ou_id)
            
            if ou_exists:
                existing_target_dn = convert_specific_parts_to_lowercase(existing_target_dn)
                if new_target_dn == existing_target_dn:
                    pass
                else:
                    move_ou(config, existing_target_dn, new_target_dn, ou_name)
            else:
                attributes = {
                    'objectClass': ['organizationalUnit'],
                    'ou': ou_name,
                    'orgUnitID': str(ou_id),
                    'orgUnitParentID': str(ou_parent_id)
                }
                conn.add(new_target_dn, attributes=attributes)
                if conn.result['result'] == 0:
                    pass
                else:
                    print(f"Failed to add OU {new_target_dn} to {config['server_uri']}. Error: {conn.result}")
    except Exception as e:
        print("LDAP error during OU creation:", str(e))

def move_user(config, user_dn, new_ou_dn):
    """
    Move a user from their current DN to a new OU.

    :param config: Dictionary containing server URI, bind DN, bind password
    :param user_dn: DN of the user to move
    :param new_ou_dn: DN of the new OU
    :return: None
    """
    server = Server(config['server_uri'])
    conn = Connection(server, config['bind_dn'], config['bind_password'], auto_bind=True)
    try:
        cn = user_dn.split(',')[0]
        rdn = user_dn.split(',')[0]
        new_user_dn = f"{cn},{new_ou_dn}"

        conn.modify_dn(user_dn, rdn, new_superior=new_ou_dn)

        if conn.result['result'] == 0:
            print(f"Successfully moved user {user_dn} to {new_user_dn}")
        else:
            raise Exception(f"Failed to move user {user_dn} to {new_user_dn}: {conn.result['description']}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.unbind()

def check_if_user_moved(config, employee_id):
    """
    Check if a user with the given employee ID exists elsewhere in the directory.

    :param config: Dictionary containing server URI, bind DN, bind password
    :param employee_id: Employee ID of the user to check
    :return: Tuple containing a boolean indicating existence and the DN if it exists
    """
    server = Server(config['server_uri'], get_info=ALL)
    try:
        with Connection(server, config['bind_dn'], config['bind_password'], auto_bind=True) as conn:
            if employee_id:
                search_filter = f'(employeeID={employee_id})'
                if conn.search(search_base=config['search_base'], search_filter=search_filter, search_scope=SUBTREE):
                    if len(conn.entries) > 0:
                        return True, conn.entries[0].entry_dn.replace(source_config['search_base'],
                                                                      target_config['search_base'])
            return False, None
    except Exception as e:
        traceback.print_exc()
        print("LDAP error during user existence check:", str(e))
        return False, None

def check_if_ou_moved(config, ou_dn):
    """
    Check if an OU with the given DN exists elsewhere in the directory.

    :param config: Dictionary containing server URI, bind DN, bind password
    :param ou_dn: Distinguished name of the OU to check
    :return: Tuple containing a boolean indicating existence and the DN if it exists
    """
    server = Server(config['server_uri'], get_info=ALL)
    try:
        with Connection(server, config['bind_dn'], config['bind_password'], auto_bind=True) as conn:
            search_filter = f'(distinguishedName={ou_dn})'
            if conn.search(search_base=config['search_base'], search_filter=search_filter, search_scope=SUBTREE):
                if len(conn.entries) > 0:
                    return True, conn.entries[0].entry_dn.replace(source_config['search_base'],
                                                                  target_config['search_base'])
            return False, None
    except Exception as e:
        traceback.print_exc()
        print("LDAP error during OU existence check:", str(e))
        return False, None

def check_and_move_child_elements(config, dn):
    """
    Check if child elements of the given DN exist elsewhere and move them if so.

    :param config: Dictionary containing server URI, bind DN, bind password
    :param dn: Distinguished name of the OU to check
    """
    server = Server(config['server_uri'], get_info=ALL)
    try:
        with Connection(server, config['bind_dn'], config['bind_password'], auto_bind=True) as conn:
            search_filter = '(|(objectClass=organizationalUnit)(objectClass=domainAccount))'
            attributes = ['distinguishedName', 'employeeID']
            if conn.search(dn, search_filter, attributes=attributes, search_scope=SUBTREE):
                for entry in conn.entries:
                    entry_dn = entry.entry_dn
                    if 'employeeID' in entry:
                        employee_id = entry.employeeID.value
                        user_moved, new_dn = check_if_user_moved(source_config, employee_id)
                        if user_moved:
                            move_user(config, entry_dn, new_dn)

                    else:
                        ou_moved, new_dn = check_if_ou_moved(source_config, entry_dn)
                        if ou_moved:
                            move_ou(config, entry_dn, new_dn, entry.ou.value)
    except Exception as e:
        traceback.print_exc()
        print("LDAP error during child element check:", str(e))

def synchronize_ous(source_config, target_config):
    """
    Synchronize OUs from the source LDAP server to the target LDAP server.

    :param source_config: Dictionary containing source server URI, bind DN, bind password, and search base
    :param target_config: Dictionary containing target server URI, bind DN, bind password, and search base
    """
    source_ous = get_all_ous(source_config)

    # Synchronize OUs from source to target
    for ou_name, dn, ou_id, ou_parent_id in source_ous:
        create_ou_if_not_exists(target_config, ou_name, dn, ou_id, ou_parent_id)

if __name__ == "__main__":
    print("Starting OU creation and modify.")
    synchronize_ous(source_config, target_config)
    print("OUs created...")
    print("OUs modified...")
