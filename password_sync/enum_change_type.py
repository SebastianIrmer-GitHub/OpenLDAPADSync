from enum import Enum

class ChangeType(Enum):
    """Enum class for representing change types in LDAP entries."""
    ADDED = "Added"
    MODIFIED = "Modified"
    DELETED = "Deleted"
    PWD_LAST_SET = "PwdLastSet"