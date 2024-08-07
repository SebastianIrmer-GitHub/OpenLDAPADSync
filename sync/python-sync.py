#!/usr/bin/env python3

import traceback
from ldap3 import Server, Connection, ALL, SUBTREE
import yaml
import logging
from colorlog import ColoredFormatter

def setup_logger(name, log_file):
    """Configures and returns a colored logger with the given name."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    fh = logging.FileHandler(log_file)

    formatter = ColoredFormatter(
        "%(log_color)s%(asctime)s.%(msecs)03d - %(levelname)-8s%(reset)s -  %(blue)s%(message)s",
        datefmt='%Y-%m-%d %H:%M:%S',
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        },
        secondary_log_colors={},
        style='%'
    )

    file_formatter = logging.Formatter(
        "%(asctime)s.%(msecs)03d - %(levelname)-8s - %(message)s",
        datefmt='%Y-%m-%d %H:%M:%S',
        style='%'
    )

    ch.setFormatter(formatter)
    fh.setFormatter(file_formatter)
    logger.addHandler(ch)
    logger.addHandler(fh)

    return logger

# Load configuration from the YAML file
with open('/etc/lsc/ou-sync.yaml', 'r') as file:
    config = yaml.safe_load(file)

# Extract source and target configurations
source_config = config['source']
target_config = config['target']

# Set up logging
logger = setup_logger('ou_sync', '/var/log/ou_sync.log')

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
                    logger.info(f"Retrieved OU: {ou_name} with DN: {dn}")
            else:
                logger.warning("No entries found.")
    except Exception as e:
        logger.error(f"LDAP error during OU retrieval: {str(e)}")
        logger.debug(traceback.format_exc())

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
                    logger.info(f"Retrieved target OU with DN: {dn}")
            else:
                logger.warning("No entries found.")
    except Exception as e:
        logger.error(f"LDAP error during target OU retrieval: {str(e)}")
        logger.debug(traceback.format_exc())

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
                logger.info(f"Moved OU {ou_name} from {old_dn} to {new_dn}")
            else:
                logger.warning(f"Failed to move OU {ou_name} from {old_dn} to {new_dn}")
    except Exception as e:
        logger.error(f"LDAP error during OU move: {str(e)}")
        logger.debug(traceback.format_exc())

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
            search_filter = f'(&(objectClass=organizationalUnit)(ouID={ou_id}))'
            conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE)
            
            if len(conn.entries) > 0:
                dn = conn.entries[0].entry_dn
                logger.info(f"OU with ID {ou_id} exists under base DN {base_dn}")
                return True, dn
            else:
                logger.info(f"OU with ID {ou_id} does not exist under base DN {base_dn}")
                return False, None
    except Exception as e:
        logger.error(f"LDAP error during OU existence check: {str(e)}")
        logger.debug(traceback.format_exc())
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
                logger.info(f"Skipping creation for special OU: {ou_name}")
                return
            
            ou_exists, existing_target_dn = ou_exist_under_base(config, base_dn, ou_id)
            
            if ou_exists:
                existing_target_dn = convert_specific_parts_to_lowercase(existing_target_dn)
                if new_target_dn == existing_target_dn:
                    logger.info(f"OU {ou_name} already exists with DN {new_target_dn}")
                else:
                    move_ou(config, existing_target_dn, new_target_dn, ou_name)
            else:
                attributes = {
                    'objectClass': ['organizationalUnit'],
                    'ou': ou_name,
                    'ouID': str(ou_id),
                    'ouParentID': str(ou_parent_id)
                }
                conn.add(new_target_dn, attributes=attributes)
                if conn.result['result'] == 0:
                    logger.info(f"Successfully added OU {ou_name} with DN {new_target_dn}")
                else:
                    logger.error(f"Failed to add OU {new_target_dn} to {config['server_uri']}. Error: {conn.result}")
    except Exception as e:
        logger.error(f"LDAP error during OU creation: {str(e)}")
        logger.debug(traceback.format_exc())

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
    logger.info("Starting OU creation and modify.")
    synchronize_ous(source_config, target_config)
    logger.info("OUs created and modified.")