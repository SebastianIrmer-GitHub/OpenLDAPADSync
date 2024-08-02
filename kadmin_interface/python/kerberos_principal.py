class Principal:
    """
    A class representing a Kerberos principal with various attributes.

    Attributes:
    user_account_control (int): The user account control settings.
    princ_expiration_time (str): The expiration time of the principal.
    pw_expiration_time (str): The password expiration time.
    username (str): The username of the principal.
    employee_id (str): The employee ID associated with the principal.
    """
    def __init__(self, user_account_control, princ_expiration_time, pw_expiration_time, username, employee_id):
        """
        Initializes a new instance of the Principal class.

        Parameters:
        user_account_control (int): The user account control settings.
        princ_expiration_time (str): The expiration time of the principal.
        pw_expiration_time (str): The password expiration time.
        username (str): The username of the principal.
        employee_id (str): The employee ID associated with the principal.
        """
        self.user_account_control = user_account_control
        self.princ_expiration_time = princ_expiration_time
        self.pw_expiration_time = pw_expiration_time
        self.username = username
        self.employee_id = employee_id

    def __repr__(self):
        """
        Returns a string representation of the Principal instance.

        Returns:
        str: A string representation of the Principal instance.
        """
        return f"Principal(username={self.username}, employee_id={self.employee_id}, princ_expiration_time={self.princ_expiration_time}, pw_expiration_time={self.pw_expiration_time}, user_account_control={self.user_account_control})"
