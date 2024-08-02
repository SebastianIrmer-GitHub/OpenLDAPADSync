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
            search_base = config['search_base']
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
            attributes = ['distinguishedName', 'orgUnitID']

            if conn.search(search_base, search_filter, attributes=attributes, search_scope=SUBTREE):
                for entry in conn.entries:
                    dn = entry.entry_dn
                    ou_id = entry.orgUnitID.value if entry.orgUnitID else None
                    ous.append((dn, ou_id))
            else:
                print("No entries found.")
    except Exception as e:
        print("LDAP error during target OU retrieval:", str(e))

    return ous

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
                print(f"Failed to move OU {old_dn} to {new_dn}: {conn.result}")
    except Exception as e:
        print("LDAP error during OU move:", str(e))

def create_ou_if_not_exists(config, target_ous, ou_name, distinguished_name, ou_id, ou_parent_id):
    """
    Create an OU in the target LDAP server if it does not already exist.

    :param config: Dictionary containing server URI, bind DN, bind password, and search base
    :param target_ous: List of tuples containing DN and ouID of target OUs
    :param ou_name: Name of the OU to create
    :param distinguished_name: Distinguished name of the OU in the source LDAP
    :param ou_id: ID of the OU
    :param ou_parent_id: Parent ID of the OU
    """
    server = Server(config['server_uri'], get_info=ALL)
    target_base = config['search_base']
    new_target_dn = distinguished_name.replace(source_config['search_base'], target_base)
    new_target_dn = convert_specific_parts_to_lowercase(new_target_dn)

    try:
        with Connection(server, config['bind_dn'], config['bind_password'], auto_bind=True) as conn:
            if ou_name in ["sudo", "automount", "Users"]:
                return

            ou_exists = any(str(ou_id) == str(target_ou_id) for _, target_ou_id in target_ous)

            if ou_exists:
                existing_target_dn = next(dn for dn, target_ou_id in target_ous if str(ou_id) == str(target_ou_id))
                existing_target_dn = convert_specific_parts_to_lowercase(existing_target_dn)
                if new_target_dn != existing_target_dn:
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
                    print(f"Successfully added OU {new_target_dn}")
                else:
                    print(f"Failed to add OU {new_target_dn} to {config['server_uri']}. Error: {conn.result}")
    except Exception as e:
        print("LDAP error during OU creation:", str(e))

def synchronize_ous(source_config, target_config):
    """
    Synchronize OUs from the source LDAP server to the target LDAP server.

    :param source_config: Dictionary containing source server URI, bind DN, bind password, and search base
    :param target_config: Dictionary containing target server URI, bind DN, bind password, and search base
    """
    source_ous = get_all_ous(source_config)
    target_ous = get_all_target_ous(target_config)
    
    # Synchronize OUs from source to target
    for ou_name, dn, ou_id, ou_parent_id in source_ous:
        create_ou_if_not_exists(target_config, target_ous, ou_name, dn, ou_id, ou_parent_id)

if __name__ == "__main__":
    print("Starting OU creation and modify.")
    synchronize_ous(source_config, target_config)
    print("OUs created...")
