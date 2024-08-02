"""
LDAP Monitor Module

This module provides a class, `LDAPMonitor`, to monitor and manage changes in LDAP entries.
It integrates with Kerberos for principal management and Active Directory for user account control.

Classes:
    ChangeType(Enum): Enum class for representing change types in LDAP entries.
    LDAPMonitor: A class to monitor and manage changes in LDAP entries.

Usage:
    To use this module, initialize the `LDAPMonitor` class with the required configuration file and log file paths, then call the `run` method to start monitoring.

Example:
    monitor = LDAPMonitor(config_file='server-config.yaml', log_file='ldap_monitor.log')
    monitor.run()
"""

import logging
from colorlog import ColoredFormatter
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, MODIFY_REPLACE
import time
import yaml
from enum import Enum
import string
import random
import os
from datetime import datetime, timezone, timedelta
import kadmin  # Assuming the compiled C extension is named kadmin
import kerberosservice


class ChangeType(Enum):
    """Enum class for representing change types in LDAP entries."""
    ADDED = "Added"
    MODIFIED = "Modified"
    DELETED = "Deleted"
    PWD_LAST_SET = "PwdLastSet"


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

    def __init__(self, config_file='server-config.yaml', log_file='ldap_monitor.log'):
        """
        Initialize the LDAPMonitor instance.

        Args:
            config_file (str): Path to the LDAP configuration file.
            log_file (str): Path to the log file.
        """
        self.logger = self.setup_logger('LDAPMonitor', log_file)
        self.ldap_config = self.load_config(config_file)
        self.ldap_conn = self.connect_ldap()
        self.last_results = None
        self.check_interval = 2
        self.domain = self.ldap_config["domain"]
        self.keytab = self.ldap_config["keytab"]

        # Initialize the Kadmin object
        self.kadmin = kadmin.Kadmin(self.keytab, self.domain)

        # Load AD configuration
        self.ad_config = self.load_config("ad-server.yaml")
        self.ad_ldap_conn = self.connect_ldap(self.ad_config)

    @staticmethod
    def setup_logger(name, log_file):
        """Configures and returns a colored logger with the given name."""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)

        # Stream handler for console output
        ch = logging.StreamHandler()
        # File handler for file output
        fh = logging.FileHandler(log_file)

        # Define log format with colors for console output
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
        # Define log format for file output
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
            dict: A dictionary containing LDAP configuration parameters.
        """
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
        return config['ldap']

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
            tuple: A tuple containing the current LDAP entries and a list of changes.
        """
        current_results = self.perform_ldap_search()

        if self.last_results is None:
            return current_results, []

        changes = []
        for current in current_results:
            dn = current.entry_dn
            last_entry = next((x for x in self.last_results if x.entry_dn == dn), None)

            if last_entry is None:
                changes.append((ChangeType.ADDED, dn))
            elif current.entry_attributes_as_dict != last_entry.entry_attributes_as_dict:
                if not self.is_pwd_last_change_only_change(current, last_entry):
                    changes.append((ChangeType.MODIFIED, dn))
                else:
                    changes.append((ChangeType.PWD_LAST_SET, dn))

        for last in self.last_results:
            dn = last.entry_dn
            if not any(x.entry_dn == dn for x in current_results):
                changes.append((ChangeType.DELETED, dn))

        return current_results, changes

    def add_principal_to_kerberos(self, username, password, pw_expiration_time, princ_expiration_time,
                                  account_disabled):
        """
        Add a principal to Kerberos.

        Args:
            username (str): The username of the principal.
            password (str): The password for the principal.
            pw_expiration_time (int): Password expiration time.
            princ_expiration_time (int): Principal expiration time.
            account_disabled (int): Whether the account is disabled.
        """
        try:
            self.kadmin.add_principal(username, password, pw_expiration_time, princ_expiration_time, account_disabled)
            self.logger.info("Principal %s added to Kerberos.", username)
        except RuntimeError as e:
            self.logger.error("Error adding principal %s: %s", username, e)

    def modify_principal_in_kerberos(self, username, princ_expiration_time, account_disabled):
        """
        Modify a principal in Kerberos.

        Args:
            username (str): The username of the principal.
            princ_expiration_time (int): Principal expiration time.
            account_disabled (int): Whether the account is disabled.
        """
        try:
            self.kadmin.modify_principal(username, princ_expiration_time, account_disabled)
            self.logger.info("Principal %s modified in Kerberos.", username)
        except RuntimeError as e:
            self.logger.error("Error modifying principal %s: %s", username, e)

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
        # Define the character sets
        letters_and_digits = string.ascii_letters + string.digits
        special_characters = string.punctuation

        # Generate random characters
        password = [
            random.choice(letters_and_digits) for _ in range(7)
        ]

        # Add one special character
        password.append(random.choice(special_characters))

        # Shuffle the password list to ensure randomness
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

    def add_pwd_last_change_to_ldap(self, dn):
        """
        Add the pwdLastChange attribute to an LDAP entry.

        Args:
            dn (str): The distinguished name of the LDAP entry.
        """
        try:
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
            self.logger.error("Exception while adding pwdLastSet to %s: %s", dn, e)

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
    def ldap_time_to_kerberos_time(ldap_timestamp):
        """
        Convert LDAP timestamp (Windows FileTime) to a Python datetime and then to Unix timestamp (Kerberos format).

        Args:
            ldap_timestamp (int): LDAP timestamp in Windows FileTime format.

        Returns:
            int: Unix timestamp in Kerberos format.
        """
        ldap_datetime = datetime(1601, 1, 1) + timedelta(microseconds=ldap_timestamp / 10)
        kerberos_timestamp = int(ldap_datetime.timestamp())
        return kerberos_timestamp

    def search_user_in_ad(self, uid):
        """
        Search for a user in AD using their sAMAccountName and return their distinguished name (DN).

        Args:
            uid (str): The sAMAccountName of the user.

        Returns:
            str: The distinguished name of the user, or None if not found.
        """
        self.ad_ldap_conn.search(
            search_base=self.ad_config['search_base'],
            search_filter=f"(sAMAccountName={uid})",
            search_scope=SUBTREE,
            attributes=['distinguishedName']
        )
        if self.ad_ldap_conn.entries:
            return self.ad_ldap_conn.entries[0].distinguishedName.value
        return None

    def update_user_account_control_in_ad(self, dn, user_account_control):
        """
        Update the userAccountControl attribute for a user in Active Directory.

        Args:
            dn (str): The distinguished name of the LDAP entry.
            user_account_control (int): The value to set for userAccountControl.
        """
        try:
            self.ad_ldap_conn.modify(
                dn,
                {'userAccountControl': [(MODIFY_REPLACE, [user_account_control])]}
            )
            if self.ad_ldap_conn.result['result'] == 0:
                self.logger.info("Updated userAccountControl to %d for %s", user_account_control, dn)
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
            self.logger.info("Retrieved list of principals from Kerberos.")
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

    def run(self):
        """
        Main function to load configuration, connect to LDAP, and monitor for changes.
        """
        try:
            initial_results = self.perform_ldap_search()
            ldap_usernames = {self.extract_username_from_dn(entry.entry_dn) for entry in initial_results}

            kerberos_principals = self.list_principals_in_kerberos()
            print(os.path.exists(self.ad_config['keytab']))
            # Check if principals exist in LDAP and delete if not
            for principal in kerberos_principals:
                if "/" in principal or "default" in principal or "admin" in principal or "bind" in principal or "testuser" in principal:
                    continue

                username = principal.split('@')[0]
                if username not in ldap_usernames:
                    self.logger.info("Principal %s in Kerberos is not present in LDAP. Deleting...", principal)
                    self.delete_principal_from_kerberos(principal)

            kerberos_principals = self.list_principals_in_kerberos()

            for entry in initial_results:
                username = self.extract_username_from_dn(entry.entry_dn)
                if not self.check_principal_exists(username, kerberos_principals):
                    self.logger.info("User %s in LDAP is not present in Kerberos.", username)
                    user_account_control = 1
                    princ_expiration_time = int(time.time())

                    if "userAccountControl" in entry:
                        try:
                            if entry.userAccountControl.value:
                                user_account_control = self.get_account_disabled(entry.userAccountControl.value)
                        except Exception as e:
                            self.logger.error("userAccountControl couldn't be determined: %s", e)

                    if "accountExpires" in entry :
                        try:
                            if entry.accountExpires.value:
                                princ_expiration_time = self.ldap_time_to_kerberos_time(entry.accountExpires.value)
                        except Exception as e:
                            self.logger.error("Principal expiration time couldn't be determined: %s", e)

                    password = self.generate_password()
                    pw_expiration_time = int(time.time())

                    self.add_principal_to_kerberos(username, password, pw_expiration_time,
                                                   princ_expiration_time, user_account_control)
                    self.save_password_to_file(username, password)
                    self.add_pwd_last_change_to_ldap(entry.entry_dn)
                    
                    if not self.ad_config['keytab']:
                        continue
                    
                    try:
                        ad_dn = self.search_user_in_ad(username)
                    except Exception as e:
                        self.logger.error("Couldn't search user in AD: %s", e)
                        continue

                            
                    if ad_dn and os.path.exists(self.ad_config['keytab']):
                        try:
                            kerberosservice.change_password_keytab(username, self.ad_config['domain'], self.ad_config['keytab'], password)                 
                        except Exception as e:
                            self.logger.error("Couldn't change password of AD User: %s", e)

                        self.update_user_account_control_in_ad(ad_dn,
                                                               entry.userAccountControl.value if entry.userAccountControl.value else 514)

                    else:
                        self.logger.error("Couldn't change user password in AD for: %s.", username)


            while True:
                current_results, changes = self.check_for_changes()

                for change_type, dn in changes:

                    username = self.extract_username_from_dn(dn)
                    self.logger.info("%s: %s", change_type.value, dn)

                    if change_type == ChangeType.DELETED:
                        principal = f"{username}@{self.domain}"
                        self.delete_principal_from_kerberos(principal)
                    elif change_type == ChangeType.PWD_LAST_SET:
                        continue
                    else:
                        self.logger.info("Waiting... %s: %s", change_type.value, dn)

                        time.sleep(20)

                        user_account_control = 1
                        princ_expiration_time = int(time.time())

                        entry = next((x for x in current_results if x.entry_dn == dn), None)

                        if "userAccountControl" in entry:
                            try:
                                user_account_control = self.get_account_disabled(entry.userAccountControl.value)
                            except Exception as e:
                                self.logger.error("userAccountControl couldn't be determined: %s", e)

                        if "accountExpires" in entry:
                            try:
                                princ_expiration_time = self.ldap_time_to_kerberos_time(entry.accountExpires.value)
                            except Exception as e:
                                self.logger.error("Prinicpal expiration time couldn't be determined: %s", e)

                        if change_type == ChangeType.ADDED:
                            password = self.generate_password()
                            pw_expiration_time = int(time.time())

                            self.add_principal_to_kerberos(username, password, pw_expiration_time,
                                                           princ_expiration_time, user_account_control)
                            self.save_password_to_file(username, password)
                            self.add_pwd_last_change_to_ldap(dn)
                            
                            if not self.ad_config['keytab']:
                                continue

                            try:
                                ad_dn = self.search_user_in_ad(username)
                            except Exception as e:
                                self.logger.error("Couldn't search user in AD: %s", e)
                                continue

                            if ad_dn and os.path.exists(self.ad_config['keytab']):
                                try:
                                    kerberosservice.change_password_keytab(username, self.ad_config['domain'], self.ad_config['keytab'], password)

                                except Exception as e:
                                    self.logger.error("Couldn't change password of AD Users: %s", e)

                                self.update_user_account_control_in_ad(ad_dn,
                                                                       entry.userAccountControl.value if entry.userAccountControl.value else 514)

                            else:
                                self.logger.error("Couldn't change user password in AD for: %s.", username)
                        elif change_type == ChangeType.MODIFIED:
                            self.modify_principal_in_kerberos(username, princ_expiration_time, user_account_control)

                self.last_results = current_results
                time.sleep(self.check_interval)
        except KeyboardInterrupt:
            self.logger.info("Stopping LDAP monitoring...")
        finally:
            self.ldap_conn.unbind()


if __name__ == "__main__":
    monitor = LDAPMonitor()

    monitor.run()
