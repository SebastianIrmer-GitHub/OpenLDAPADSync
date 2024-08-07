import logging
from colorlog import ColoredFormatter
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, MODIFY_REPLACE
import time
import yaml
import string
import random
import os
from datetime import datetime, timezone, timedelta
import kadmin
import kerberosservice
import threading
from kerberos_principal import Principal
from enum_change_type import ChangeType

class LDAPMonitor:
    """
    A class to monitor and manage changes in LDAP entries.

    Attributes:
        logger (logging.Logger): Logger for the class.
        ldap_config (dict): Configuration parameters for LDAP.
        ldap_conn (ldap3.Connection): LDAP connection object.
        last_results (list): Last fetched LDAP results.
        check_interval (int): Interval between checks.
        domain (str): Domain name.
        keytab (str): Keytab file.
        kadmin (kadmin.Kadmin): Kadmin object for Kerberos operations.
        ad_config (dict): Configuration parameters for Active Directory.
        ad_ldap_conn (ldap3.Connection): LDAP connection object for Active Directory.
    """

    def __init__(self, config_file='server-config.yaml', log_file='ldap_monitor.log', polling_interval=2):
        """
        Initialize the LDAPMonitor instance.

        Args:
            config_file (str): Path to the LDAP configuration file.
            log_file (str): Path to the log file.
        """
        self.logger = self.setup_logger('LDAPMonitor', log_file)
        self.config = self.load_config(config_file)
        self.ldap_config = self.config['ldap']
        self.ad_config = self.config['ad']
        
        self.ldap_conn = self.connect_ldap(self.ldap_config)
        self.ad_ldap_conn = self.connect_ldap(self.ad_config)
        
        self.last_results = None
        self.check_interval = polling_interval
        self.domain = self.ldap_config["domain"]
        self.keytab = self.ldap_config["keytab"]

        # Initialize the Kadmin object
        self.kadmin = kadmin.Kadmin(self.keytab, self.domain)
        self.ldap_usernames = []
        self.kerberos_principals = []
        

    @staticmethod
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

    @staticmethod
    def load_config(config_file):
        """
        Load the LDAP configuration from a YAML file.

        Args:
            config_file (str): Path to the configuration file.

        Returns:
            dict: A dictionary containing configuration parameters.
        """
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
        return config

    def connect_ldap(self, ldap_config=None):
        """
        Connect to the LDAP server.

        Args:
            ldap_config (dict): LDAP configuration parameters.

        Returns:
            ldap3.Connection: An LDAP connection object.
        """
        if not ldap_config:
            ldap_config = self.ldap_config

        server = Server(ldap_config['server'], get_info=ALL)
        conn = Connection(server, ldap_config['user'], ldap_config['password'], auto_bind=True)
        return conn

    def perform_ldap_search(self):
        """
        Perform an LDAP search based on the configuration.

        Returns:
            list: A list of LDAP entries matching the search criteria.
        """
        attributes = ALL_ATTRIBUTES if "*" in self.ldap_config['attributes'] else self.ldap_config['attributes']
        self.ldap_conn.search(
            self.ldap_config['search_base'],
            self.ldap_config['search_filter'],
            SUBTREE,
            attributes=attributes
        )
        return self.ldap_conn.entries

    def check_for_changes(self):
        """
        Check for changes in the LDAP entries compared to the last results.

        Returns:
            dict: A dictionary containing the current LDAP entries and a dict of changes.
        """
        current_results = self.perform_ldap_search()
        if self.last_results is None:
            return {"current_results": current_results, "changes": {}}

        changes = {}
        
    
        current_dict = {}
        for entry in current_results:
            employee_id = entry.employeeID.value if hasattr(entry.employeeID, 'value') else entry.employeeID
            current_dict[employee_id] = entry

        last_dict = {}
        for entry in self.last_results:
            employee_id = entry.employeeID.value if hasattr(entry.employeeID, 'value') else entry.employeeID
            last_dict[employee_id] = entry

    
        for employee_id, current_entry in current_dict.items():
            last_entry = last_dict.get(employee_id)
            uid = current_entry.uid

            if last_entry is None:
                changes[employee_id] = {
                    "change_type": ChangeType.ADDED,
                    "uid": uid,
                    "employee_id": employee_id
                }
            elif current_entry.entry_attributes_as_dict != last_entry.entry_attributes_as_dict:
                if not self.is_pwd_last_change_only_change(current_entry, last_entry):
                    changes[employee_id] = {
                        "change_type": ChangeType.MODIFIED,
                        "uid": uid,
                        "employee_id": employee_id
                    }
                else:
                    changes[employee_id] = {
                        "change_type": ChangeType.PWD_LAST_SET,
                        "uid": uid,
                        "employee_id": employee_id
                    }

        # Check for deleted entries
        for employee_id, last_entry in last_dict.items():
            if employee_id not in current_dict:
                changes[employee_id] = {
                    "change_type": ChangeType.DELETED,
                    "uid": last_entry.uid,
                    "employee_id": employee_id
                }
    
        return {"current_results": current_results, "changes": changes}

    def add_principal_to_kerberos(self, password, principal):
        """
        Add a principal to Kerberos.

        Args:
            principal (Principal): The principal to add.
        """
        try:
            self.kadmin.add_principal(
                principal.username,
                password,
                principal.pw_expiration_time,
                principal.princ_expiration_time,
                principal.user_account_control
            )
            self.logger.info("Principal %s added to Kerberos.", principal.username)
        except RuntimeError as e:
            self.logger.error("Error adding principal %s: %s", principal.username, e)

    def modify_principal_in_kerberos(self, principal):
        """
        Modify a principal in Kerberos.

        Args:
            principal (Principal): The principal to modify.
        """
        try:
            self.kadmin.modify_principal(
                str(principal.username),
                principal.princ_expiration_time,
                principal.user_account_control
            )
            self.logger.info("Principal %s modified in Kerberos.", principal.username)
        except Exception as e:
            self.logger.error("Error modifying principal %s: %s", principal.username, e)

    @staticmethod
    def extract_username_from_dn(dn):
        """
        Extract the username from the distinguished name (DN).

        Args:
            dn (str): The distinguished name.

        Returns:
            str: The extracted username.
        """
        return dn.split(',')[0].split('=')[1]

    @staticmethod
    def generate_password():
        """
        Generate a random 8-character password including at least one special character.

        Returns:
            str: The generated password.
        """
        letters_and_digits = string.ascii_letters + string.digits
        special_characters = string.punctuation

        password = [
            random.choice(letters_and_digits) for _ in range(7)
        ]

        password.append(random.choice(special_characters))

        random.shuffle(password)

        return ''.join(password)

    @staticmethod
    def save_password_to_file(username, password):
        """
        Save the password to a file named after the username.

        Args:
            username (str): The username.
            password (str): The password.
        """
        os.makedirs('user_passwords', exist_ok=True)
        with open(f'user_passwords/{username}.txt', 'w') as f:
            f.write(password)

    def delete_principal_from_kerberos(self, principal):
        """
        Delete a principal from Kerberos.

        Args:
            principal (str): The principal to be deleted.
        """
        try:
            self.kadmin.delete_principal(principal)
            self.logger.info("Principal %s deleted from Kerberos.", principal)
        except RuntimeError as e:
            self.logger.error("Error deleting principal %s: %s", principal, e)

    @staticmethod
    def get_account_disabled(user_account_control):
        """
        Determine if the account is disabled based on userAccountControl attribute.

        Args:
            user_account_control (int): The userAccountControl attribute from LDAP.

        Returns:
            int: 1 if the account is disabled, 0 otherwise.
        """
        return 1 if user_account_control & 0x2 else 0

    @staticmethod
    def convert_to_generalized_time(timestamp=None):
        """
        Convert the given timestamp to LDAP Generalized Time format (YYYYMMDDHHMMSSZ).

        Args:
            timestamp (float): The timestamp to convert. If None, use the current time.

        Returns:
            str: The time in LDAP Generalized Time format.
        """
        now = datetime.now(timezone.utc) if timestamp is None else datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return now.strftime('%Y%m%d%H%M%SZ')

    def add_pwd_last_change_to_ldap(self, principal):
        """
        Add the pwdLastChange attribute to an LDAP entry by employeeID.

        Args:
            principal (Principal): The principal containing the employeeID.
        """
        try:
            search_filter = f"(employeeID={principal.employee_id})"
            
            search_attributes = ['distinguishedName']

            
            self.ldap_conn.search(self.ldap_config['search_base'], search_filter, SUBTREE, attributes=search_attributes)
            result = self.ldap_conn.entries

            if not result:
                self.logger.error("No LDAP entry found for employeeID %s", principal.employee_id)
                return

            dn = result[0].entry_dn  #

            
            generalized_time = self.convert_to_generalized_time()
            
            self.ldap_conn.modify(
                dn,
                {'pwdLastSet': [(MODIFY_REPLACE, [generalized_time])]}
            )

            if self.ldap_conn.result['result'] == 0:
                self.logger.info("Added pwdLastSet to %s", dn)
            else:
                self.logger.error("Failed to add pwdLastSet to %s: %s", dn, self.ldap_conn.result['description'])

        except Exception as e:
            self.logger.error("Exception while adding pwdLastSet to employeeID %s: %s", principal.employee_id, e)


    @staticmethod
    def is_pwd_last_change_only_change(current, last):
        """
        Check if the only change between current and last is the addition of the pwdLastChange attribute.

        Args:
            current (ldap3.Entry): The current LDAP entry.
            last (ldap3.Entry): The previous LDAP entry.

        Returns:
            bool: True if the only change is pwdLastChange, False otherwise.
        """
        current_attrs = current.entry_attributes_as_dict
        last_attrs = last.entry_attributes_as_dict

        if 'pwdLastSet' in current_attrs and 'pwdLastSet' in last_attrs:
            temp_current_attrs = current_attrs.copy()
            temp_last_attrs = last_attrs.copy()
            temp_current_attrs.pop('pwdLastSet')
            temp_last_attrs.pop('pwdLastSet')
            return temp_current_attrs == temp_last_attrs

        if 'pwdLastSet' in current_attrs and 'pwdLastSet' not in last_attrs:
            temp_current_attrs = current_attrs.copy()
            temp_current_attrs.pop('pwdLastSet')
            return temp_current_attrs == last_attrs

        return False

    @staticmethod
    def ldap_time_to_kerberos_time(shadow_expire):
        """
        Convert shadowExpire (number of days since Unix epoch) to Unix timestamp (Kerberos format).

        Args:
            ldap_timestamp (int): LDAP timestamp in Windows FileTime format.

        Returns:
            int: Unix timestamp in Kerberos format.
        """
        kerberos_timestamp = shadow_expire * 86400

        return kerberos_timestamp
    # ppCGCoxO
    @staticmethod
    def kerberos_time_to_ldap_time(kerberos_timestamp):
        """
        Convert a Unix timestamp (Kerberos format) to LDAP timestamp (Windows FileTime format).

        Args:
            kerberos_timestamp (int): Unix timestamp in Kerberos format.

        Returns:
            int: LDAP timestamp in Windows FileTime format.
        """
        epoch_start = datetime(1601, 1, 1, tzinfo=timezone.utc)  
        kerberos_datetime = datetime.fromtimestamp(kerberos_timestamp, tz=timezone.utc)  
        ldap_time = int((kerberos_datetime - epoch_start).total_seconds() * 10**7)
        return ldap_time
    
    def update_user_account_control_in_ad(self, employee_id, user_account_control):
        """
        Update the userAccountControl attribute for a user in Active Directory.

        Args:
            employee_id (str): The employeeID of the LDAP entry.
            user_account_control (int): The value to set for userAccountControl.
        """
        dn, _ = self.search_user_in_ad_by_employee_id(employee_id)
        if not dn:
            self.logger.error("Failed to find DN for employeeID %s", employee_id)
            return

        try:
            self.ad_ldap_conn.modify(
                dn,
                {'userAccountControl': [(MODIFY_REPLACE, [user_account_control])]}
            )
            if self.ad_ldap_conn.result['result'] == 0:
                pass
            else:
                self.logger.error("Failed to update userAccountControl for %s: %s", dn,
                                  self.ad_ldap_conn.result['description'])
        except Exception as e:
            self.logger.error("Exception while updating userAccountControl for %s: %s", dn, e)

    def list_principals_in_kerberos(self):
        """
        List all principals in Kerberos database.

        Returns:
            list: A list of all principal names.
        """
        try:
            principals = self.kadmin.list_principals()
            return principals
        except RuntimeError as e:
            self.logger.error("Error listing principals: %s", e)
            return []

    def check_principal_exists(self, uid, principals):
        """
        Check if a principal exists in Kerberos based on the UID from OpenLDAP.

        Args:
            uid (str): The UID to check.
            principals (list): List of Principals in Kerberos Database.
        Returns:
            bool: True if the principal exists, False otherwise.
        """
        principal = f"{uid}@{self.domain}"

        if principal in principals:
            return True
        else:
            self.logger.info("Principal %s does not exist in Kerberos.", principal)
            return False

    def search_user_in_ad_by_employee_id(self, employee_id):
        """
        Search for a user in AD using their employeeID and return their distinguished name (DN).

        Args:
            employee_id (str): The employeeID of the user.

        Returns:
            str: The distinguished name of the user, or None if not found.
        """
        self.ad_ldap_conn.search(
            search_base=self.ad_config['search_base'],
            search_filter=f"(employeeID={employee_id})",
            search_scope=SUBTREE,
            attributes=['distinguishedName', 'sAMAccountName']
        )
        if self.ad_ldap_conn.entries:  
            dn = self.ad_ldap_conn.entries[0].distinguishedName.value
            sam_account_name = self.ad_ldap_conn.entries[0].sAMAccountName.value
            return dn, sam_account_name
        return None, None

    def object_exists_in_ad_by_employee_id(self, employee_id):
        """
        Check if an object exists in Active Directory using employeeID.

        Args:
            employee_id (str): The employeeID of the object.

        Returns:
            bool: True if the object exists, False otherwise.
        """
        self.ad_ldap_conn.search(
            search_base=self.ad_config['search_base'],
            search_filter=f"(employeeID={employee_id})",
            search_scope=SUBTREE,
            attributes=['distinguishedName']
        )
        return bool(self.ad_ldap_conn.entries)

    def run(self):
        """
        Main function to load configuration, connect to LDAP, and monitor for changes.
        """
        self.logger.info("Running LDAP-Kerberos Sync...")
        try:
            self.initialize_monitoring()
            self.clean_up_kerberos()
            self.sync_ldap_to_kerberos()
            self.monitor_changes()
        except KeyboardInterrupt:
            self.logger.info("Stopping LDAP monitoring...")
        finally:
            self.ldap_conn.unbind()

    def initialize_monitoring(self):
        """
        Initialize the monitoring by performing an initial LDAP search and setting up usernames.
        """
        initial_results = self.perform_ldap_search()
        self.ldap_usernames = {str(entry.uid) for entry in initial_results}
        self.kerberos_principals = self.list_principals_in_kerberos()

    def clean_up_kerberos(self):
        """
        Clean up Kerberos principals that are not present in LDAP.
        """
        for principal in self.kerberos_principals:
            if self.is_special_principal(principal):
                continue
                
            username = principal.split('@')[0]

            if username not in self.ldap_usernames:
                self.logger.info("Principal %s in Kerberos is not present in LDAP. Deleting...", principal)
                self.delete_principal_from_kerberos(principal)

    def is_special_principal(self, principal):
        """
        Check if the principal is a special one that should be skipped.
        """
        return "/" in principal or "default" in principal or "admin" in principal or "bind" in principal

    def sync_ldap_to_kerberos(self):
        """
        Sync LDAP users to Kerberos, adding any missing principals.
        """
        initial_results = self.perform_ldap_search()
        for entry in initial_results:
            username = str(entry.uid)
            if not self.check_principal_exists(username, self.kerberos_principals):
                user_account_control = self.get_user_account_control(entry)
                princ_expiration_time = self.get_principal_expiration_time(entry)
                pw_expiration_time = int(time.time())
                
                principal = Principal(
                    user_account_control,
                    princ_expiration_time,
                    pw_expiration_time,
                    username,
                    entry.employeeID.value
                )
                threading.Thread(target=self.handle_new_ldap_user, args=(principal,)).start()
                
    def handle_new_ldap_user(self, principal):
        """
        Handle the case where a new LDAP user needs to be added to Kerberos.
        """
        
        password = "Abc1234"  
       
        self.add_principal_to_kerberos(password, principal)
        self.save_password_to_file(principal.username, password)
        self.add_pwd_last_change_to_ldap(principal)
        
        if not self.ad_config['keytab']:
            return

        self.update_ad_user(principal, password)

    def get_user_account_control(self, entry):
        """
        Get the user account control value from the LDAP entry.
        """
        user_account_control = 1
        if "userAccountControl" in entry:
            try:
                if entry.userAccountControl.value:
                    user_account_control = self.get_account_disabled(entry.userAccountControl.value)
            except Exception as e:
                self.logger.error("userAccountControl couldn't be determined: %s", e)
        return user_account_control
    
    def get_principal_expiration_time(self, entry):
        """
        Get the principal expiration time from the LDAP entry.
        """
        princ_expiration_time = int(time.time())
        if "shadowExpire" in entry:
            try:
                if entry.shadowExpire.value:
                    princ_expiration_time = self.ldap_time_to_kerberos_time(entry.shadowExpire.value)
                    print(princ_expiration_time)
            except Exception as e:
                self.logger.error("Principal expiration time couldn't be determined: %s", e)
        return princ_expiration_time

    def update_account_expires_in_ad(self, employee_id, kerberos_timestamp):
        """
        Update the shadowExpire attribute in Active Directory.

        Args:
            employee_id (str): The employeeID of the LDAP entry.
            kerberos_timestamp (int): The Unix timestamp in Kerberos format.
        """
        dn, _ = self.search_user_in_ad_by_employee_id(employee_id)
        if not dn:
            self.logger.error("Failed to find DN for employeeID %s", employee_id)
            return

        ldap_timestamp = self.kerberos_time_to_ldap_time(kerberos_timestamp)
        try:
            self.ad_ldap_conn.modify(
                dn,
                {'shadowExpire': [(MODIFY_REPLACE, [ldap_timestamp])]}
            )
            if self.ad_ldap_conn.result['result'] == 0:
                pass
            else:
                self.logger.error("Failed to update shadowExpire for %s: %s", dn, self.ad_ldap_conn.result['description'])
        except Exception as e:
            self.logger.error("Exception while updating shadowExpire for %s: %s", dn, e)

    def update_ad_user(self, principal, password):
        """
        Update the AD user with the new password and account control settings.
        """
        
        if not os.path.exists(self.ad_config['keytab']):
            self.logger.info("Keytab file for AD-Sync does not exist, not syncing...")
            return
        
        try:
            _, ad_sam_account_name = self.search_user_in_ad_by_employee_id(principal.employee_id)
        except Exception as e:
            self.logger.error("Couldn't search user in AD: %s", e)
            return

        retries = 5
        for attempt in range(retries):
            
            if ad_sam_account_name:
                try:
                    kerberosservice.change_password_keytab(ad_sam_account_name, self.ad_config['domain'], self.ad_config['keytab'], password)
                except Exception as e:
                    self.logger.error("Couldn't change password of AD User: %s", e)
                    continue
                
                ## This is performed by the LSC Script, not necessary here 
                # self.update_user_account_control_in_ad(principal.employee_id, 512 if principal.user_account_control == 0 else 514)
                # self.update_account_expires_in_ad(principal.employee_id, principal.princ_expiration_time)
                self.logger.info("User with employeeID %s updated in AD {sAMAccountName: %s}", principal.employee_id, ad_sam_account_name)
                break 
            else:
                self.logger.info("User not found in AD, retrying in 2 miuntes... (Attempt %d/%d)", attempt + 1, retries)
                time.sleep(20)
                _, ad_sam_account_name = self.search_user_in_ad_by_employee_id(principal.employee_id)

    def monitor_changes(self):
        """
        Monitor LDAP for changes and handle them accordingly.
        """
        while True:
            result = self.check_for_changes()
            current_results = result["current_results"]
            changes = result["changes"]
            self.handle_changes(changes, current_results)
            self.last_results = current_results
            time.sleep(self.check_interval)

    def handle_changes(self, changes, current_results):
        """
        Handle the changes detected in the LDAP entries.
        """
        for employee_id, change in changes.items():
            change_type = change["change_type"]
            uid = str(change["uid"])
            self.logger.info("%s: EmployeeID %s (UID: %s)", change_type.value, employee_id, uid)

            if change_type == ChangeType.DELETED:
                principal = f"{uid}@{self.domain}"
                self.delete_principal_from_kerberos(principal)
            elif change_type == ChangeType.PWD_LAST_SET:
                continue
            else:
                threading.Thread(target=self.handle_non_deleted_changes, args=(change_type, employee_id, current_results)).start()

    def handle_non_deleted_changes(self, change_type, employee_id, current_results):
        """
        Handle changes that are not deletions.
        """
        entry = next((x for x in current_results if (x.employeeID.value if hasattr(x.employeeID, 'value') else x.employeeID) == employee_id), None)
        username = entry.uid.value
        
        self.ldap_usernames = {str(entry.uid) for entry in current_results}
        self.kerberos_principals = self.list_principals_in_kerberos()
        user_account_control = self.get_user_account_control(entry)
        princ_expiration_time = self.get_principal_expiration_time(entry)
        pw_expiration_time = int(time.time())
        
        principal = Principal(
            user_account_control,
            princ_expiration_time,
            pw_expiration_time,
            username,
            entry.employeeID.value
        )
                
        if change_type == ChangeType.ADDED:
            self.handle_new_ldap_user(principal)
        elif change_type == ChangeType.MODIFIED:
            if not self.check_principal_exists(username, self.kerberos_principals):
                self.handle_new_ldap_user(principal)
            else:
                self.modify_principal_in_kerberos(principal)
                
        # cleaning remaining entries 
        self.clean_up_kerberos()
            
if __name__ == "__main__":
    monitor = LDAPMonitor()
    monitor.run()
