import datetime
import random
import string
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_ADD
import argparse
import subprocess

target_server_uri = 'ldap://localhost:389'
target_bind_dn = 'cn=admin,dc=openldap,dc=krb,dc=uni-magdeburg,dc=de'
target_bind_password = 'Abc1234'
target_base_dn = 'ou=Domain Users,dc=openldap,dc=krb,dc=uni-magdeburg,dc=de'

status_of_user = ['Rentner', 'Aktiv', 'Ruhend', 'Ausgetreten']
gender_of_user = ['male', 'female', 'other']

type_of_dist_group = ['2', '4', '8']
type_of_sec_group = ['-2147483646', '-2147483644', '-2147483640']

# 2 - Global, 4 - Local 8 - Universal
# -2147483646 - Global, -2147483644 - Local, -2147483640 - Universal

def generate_random_string(length=8):
    """
    Generate a random string of letters and digits.

    :param length: Length of the random string (default is 8)
    :return: Random string
    """
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for _ in range(length))


def create_ou(server_uri, bind_dn, bind_password, ou_name, parent_dn):
    """
    Create an Organizational Unit (OU) in the LDAP directory with the parent OU ID.

    :param server_uri: URI of the LDAP server
    :param bind_dn: DN to bind with
    :param bind_password: Password to bind with
    :param ou_name: Name of the OU to create
    :param parent_dn: DN of the parent entry
    :return: None
    """
    server = Server(server_uri, get_info=ALL)
    parent_ou_id = ""
    try:
        with Connection(server, bind_dn, bind_password, auto_bind=True) as conn:
            # Search for the parent OU's ouID
            if parent_dn:

                conn.search(parent_dn, '(objectClass=customOU)', attributes=['ouID'])
                if conn.entries:
                    parent_ou_id = conn.entries[0].ouID.value

            # Generate a new ouID for the current OU
            ou_id = str(random.randint(1000, 9999))

            ou_dn = f'ou={ou_name},{parent_dn}'
            attributes = {
                'objectClass': ['customOU', 'organizationalUnit', 'top'],
                'ou': ou_name,
                'ouID': ou_id,
                'ouParentID': parent_ou_id
            }

            # Add the new OU
            conn.add(ou_dn, attributes=attributes)
            result = conn.result

            if result['result'] == 0:
                print(f"OU {ou_name} created successfully at {ou_dn} with ouID: {ou_id} and ouParentID: {parent_ou_id}")
            else:
                print(f"Failed to create OU {ou_name}: {result['description']} - {result['message']}")
    except Exception as e:
        print("LDAP error:", str(e))


def search_users(server_uri, bind_dn, bind_password, search_base, object_classes):
    """
    Search for users in the LDAP directory.

    :param server_uri: URI of the LDAP server
    :param bind_dn: DN to bind with
    :param bind_password: Password to bind with
    :param search_base: Base DN to search from
    :param object_classes: List of object classes to search for
    :return: List of user DNs
    """
    server = Server(server_uri, get_info=ALL)
    user_dns = []
    try:
        with Connection(server, bind_dn, bind_password, auto_bind=True) as conn:
            search_filter = '(|' + ''.join(['(objectClass={})'.format(cls) for cls in object_classes]) + ')'
            conn.search(search_base, search_filter, attributes=['uid'])
            for entry in conn.entries:
                user_dns.append(entry.entry_dn)


    except Exception as e:
        print("LDAP error during search:", str(e))

    return user_dns


def move_user(server_uri, bind_dn, bind_password, user_dn, new_ou_dn):
    """
    Move a user from their current DN to a new OU.

    :param server_uri: URI of the LDAP server
    :param bind_dn: DN to bind with
    :param bind_password: Password to bind with
    :param user_dn: DN of the user to move
    :param new_ou_dn: DN of the new OU
    :return: None
    """
    server = Server(server_uri)
    conn = Connection(server, bind_dn, bind_password, auto_bind=True)
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


def generate_and_add_ous(num_ous, server_uri, bind_dn, bind_password, base_dn):
    """
    Generate and add multiple OUs to the LDAP directory.

    :param num_ous: Number of OUs to create
    :param server_uri: URI of the LDAP server
    :param bind_dn: DN to bind with
    :param bind_password: Password to bind with
    :param base_dn: Base DN under which to create the OUs
    :return: List of created OU DNs
    """
    ou_dns = []
    for _ in range(num_ous):
        depth = random.randint(1, 5)  # Random depth between 1 and 5 levels
        parent_dn = base_dn
        for d in range(depth):
            ou_name = generate_random_string()
            create_ou(server_uri, bind_dn, bind_password, ou_name, parent_dn)
            parent_dn = f'ou={ou_name},{parent_dn}'  # Update parent DN for the next level
            ou_dns.append(parent_dn)

            num_additional_ous = random.randint(1, 3)
            for _ in range(num_additional_ous):
                additional_ou_name = generate_random_string()
                create_ou(server_uri, bind_dn, bind_password, additional_ou_name, parent_dn)
                additional_ou_dn = f'ou={additional_ou_name},{parent_dn}'
                ou_dns.append(additional_ou_dn)
    return ou_dns


def create_group(server_uri, bind_dn, bind_password, base_dn, cn, group_type):
    group_dn = f"cn={cn},{base_dn}"

    group_attributes = {
        'objectClass': ['customGroup', 'top'],
        'cn': cn,
        'uniqueGroupID': str(random.randint(1000, 9999)),
        'gidNumber': str(random.randint(1000, 9999)),
        'groupType': random.choice(group_type),
    }

    server = Server(server_uri, get_info=ALL)
    try:
        with Connection(server, bind_dn, bind_password, auto_bind=True) as conn:
            conn.add(group_dn, attributes=group_attributes)
            result = conn.result

            if result['result'] == 0:
                print(f"Group {cn} added successfully with DN: {group_dn}")
                return group_dn, group_attributes['groupType']
            else:
                print(f"Failed to add group {cn}: {result['description']} - {result}")
                return None, None
    except Exception as e:
        print("LDAP error:", str(e))
        return None, None



def add_user(server_uri, bind_dn, bind_password, base_dn, uid, cn, sn):
    """
    Add a user to the LDAP directory.

    :param server_uri: URI of the LDAP server
    :param bind_dn: DN to bind with
    :param bind_password: Password to bind with
    :param base_dn: Base DN under which to add the user
    :param uid: User ID
    :param cn: Common name of the user
    :param sn: Surname of the user
    :return: None
    """
    user_dn = f'uid={uid},{base_dn}'
    current_time = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%SZ')
    expiration_time = (datetime.datetime.utcnow() + datetime.timedelta(days=10)).strftime('%Y%m%d%H%M%SZ')

    user_attributes = {
        'objectClass': ['domainAccount', 'top'],
        'cn': cn,
        'sn': sn,
        'uid': uid,
        'gidNumber': "1001",
        'uidNumber': str(random.randint(1000, 9999)),
        'homeDirectory': f"/home/{uid}",
        'givenName': sn,
        'name': cn,
        'gender': random.choice(gender_of_user),
        'employeeID': str(random.randint(1000, 9999)),
        'userStatus': random.choice(status_of_user),
        'userStatusValidFrom': current_time,
        'userAccountControl': 512,
        'accountExpiration': expiration_time
    }

    server = Server(server_uri, get_info=ALL)
    try:
        with Connection(server, bind_dn, bind_password, auto_bind=True) as conn:
            conn.add(user_dn, attributes=user_attributes)
            result = conn.result

            if result['result'] == 0:
                print(f"User {uid} added successfully")
            else:
                print(f"Failed to add user {uid}: {result['description']} - {result['message']}")
    except Exception as e:
        print("LDAP error:", str(e))


def generate_and_add_users(num_users, server_uri, bind_dn, bind_password, base_dn, kdc_exist):
    """
    Generate and add multiple users to the LDAP directory.

    :param num_users: Number of users to create
    :param server_uri: URI of the LDAP server
    :param bind_dn: DN to bind with
    :param bind_password: Password to bind with
    :param base_dn: Base DN under which to add the users
    :return: None
    """
    for _ in range(num_users):
        uid = generate_random_string()
        cn = f'User_{uid}'
        sn = 'Doe'

        add_user(server_uri, bind_dn, bind_password, base_dn, uid, cn, sn)

        if kdc_exist:
            try:
                # Command to add a principal in Kerberos using kadmin
                command = ['sudo', 'kadmin', '-p', 'admin/admin', '-K', 'admin.keytab', 'add', '--use-defaults', '-p',
                           'Abc1234', uid]
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                if result.returncode == 0:
                    print(f"Kerberos principal for {uid} added successfully.")
                else:
                    print(f"Failed to add Kerberos principal for {uid}: {result.stderr}")
            except subprocess.CalledProcessError as e:
                print(f"Error occurred while adding Kerberos principal for {uid}: {e.output}")


def distribute_users_among_ous(server_uri, bind_dn, bind_password, users, ou_dns):
    """
    Distribute users among the created OUs.

    :param server_uri: URI of the LDAP server
    :param bind_dn: DN to bind with
    :param bind_password: Password to bind with
    :param users: List of user DNs to distribute
    :param ou_dns: List of OU DNs among which to distribute the users
    :return: None
    """
    for user_dn in users:
        new_ou_dn = random.choice(ou_dns)
        move_user(server_uri, bind_dn, bind_password, user_dn, new_ou_dn)


def generate_and_add_groups(server_uri, bind_dn, bind_password, base_dn, num_dist_groups, num_sec_groups):
    dist_group_dns = []
    sec_group_dns = []

    for _ in range(num_dist_groups):
        cn = generate_random_string()
        group_dn, group_type = create_group(server_uri, bind_dn, bind_password, base_dn, cn, type_of_dist_group)
        if group_dn:
            dist_group_dns.append((group_dn, group_type))

    for _ in range(num_sec_groups):
        cn = generate_random_string()
        group_dn, group_type = create_group(server_uri, bind_dn, bind_password, base_dn, cn, type_of_sec_group)
        if group_dn:
            sec_group_dns.append((group_dn, group_type))

    return dist_group_dns, sec_group_dns

def add_members_to_groups(server_uri, bind_dn, bind_password, users, dist_groups, sec_groups):
    """
    Add random members to the created groups, ensuring the constraints for group memberships are met.

    :param server_uri: URI of the LDAP server
    :param bind_dn: DN to bind with
    :param bind_password: Password to bind with
    :param users: List of user DNs to distribute
    :param dist_groups: List of distribution group DNs
    :param sec_groups: List of security group DNs
    :return: None
    """
    server = Server(server_uri, get_info=ALL)

    try:
        with Connection(server, bind_dn, bind_password, auto_bind=True) as conn:
            for group_dn, group_type in dist_groups:
                if group_type == '2':  # Distribution group
                    members = random.sample(users + [dn for dn, g_type in dist_groups if g_type == '2'], random.randint(1, 5))
                elif group_type == '4':
                    members = random.sample(users + [dn for dn, g_type in sec_groups], random.randint(1, 5))
                elif group_type == '8':
                    members = random.sample(users + [dn for dn, g_type in dist_groups if g_type != '4'], random.randint(1, 5))

                conn.modify(group_dn, {'uniqueMember': [(MODIFY_ADD, members)]})
                print(f"Added members {members} to distribution group {group_dn}")
                result = conn.result

                if result['result'] == 0:
                    print(f"User {group_dn} added successfully")
                else:
                    print(f"Failed to add user {group_dn}: {result['description']} - {result['message']}")

            for group_dn, group_type in sec_groups:
                if group_type == '-2147483646':
                    members = random.sample(users + [dn for dn, g_type in sec_groups if g_type == '-2147483646'], random.randint(1, 5))
                elif group_type == '-2147483644':
                    members = random.sample(users + [dn for dn, g_type in sec_groups], random.randint(1, 5))
                elif group_type == '-2147483640':
                    members = random.sample(users + [dn for dn, g_type in sec_groups if g_type != '-2147483644'], random.randint(1, 5))

                conn.modify(group_dn, {'uniqueMember': [(MODIFY_ADD, members)]})
                result = conn.result

                if result['result'] == 0:
                    print(f"User {group_dn} added successfully")
                else:
                    print(f"Failed to add user {group_dn}: {result['description']} - {result['message']}")


    except Exception as e:
        print("LDAP error while adding members:", str(e))
if __name__ == "__main__":
    # Generate and add 20 users

    parser = argparse.ArgumentParser(description='LDAP User and OU Management')
    parser.add_argument('-kdc_exist', type=int, required=False, help='Check if KDC exists (1/0)')

    args = parser.parse_args()
    if args.kdc_exist:
        kdc_exist = bool(args.kdc_exist)
    else:
        kdc_exist = False
    ou_dns = generate_and_add_ous(7, target_server_uri, target_bind_dn, target_bind_password, target_base_dn)


    generate_and_add_users(20, target_server_uri, target_bind_dn, target_bind_password, target_base_dn, kdc_exist)
    # Generate and add 7 OUs
    object_classes = ['domainAccount']

    # Search for users in the base DN
    user_dns = search_users(target_server_uri, target_bind_dn, target_bind_password, target_base_dn, object_classes)
    print(f"Found users: {user_dns}")
    print(f"Total number of users: {len(user_dns)}")

    # Distribute users among the created OUs
    distribute_users_among_ous(target_server_uri, target_bind_dn, target_bind_password, user_dns, ou_dns)
    updated_user_dns = search_users(target_server_uri, target_bind_dn, target_bind_password, target_base_dn,
                                    object_classes)
    group_dn = "ou=Groups,dc=openldap,dc=krb,dc=uni-magdeburg,dc=de"

    dist_groups, sec_groups = generate_and_add_groups(target_server_uri, target_bind_dn, target_bind_password, group_dn, 5, 20)
    add_members_to_groups(target_server_uri, target_bind_dn, target_bind_password, updated_user_dns, dist_groups, sec_groups)

    print("Users distributed among OUs successfully.")
