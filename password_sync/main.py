from ldap_monitor import LDAPMonitor

def main():
    """
    Main function to initialize and run the LDAPMonitor.

    This function creates an instance of LDAPMonitor with the specified 
    configuration and log files, and then starts the monitor.

    Parameters:
    None

    Returns:
    None
    """
    monitor = LDAPMonitor(config_file='server-config.yaml', log_file='ldap_monitor.log')
    monitor.run()

if __name__ == "__main__":
    main()
