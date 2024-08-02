#!/bin/bash

AUDIT_LOG="/var/log/openldap/auditlog.log"
LAST_POSITION_FILE="/var/log/openldap/auditlog.log.position"

echo "Starting script at $(date)"

# Read the last processed position
if [ -f "$LAST_POSITION_FILE" ]; then
  last_position=$(cat "$LAST_POSITION_FILE")
  echo "Last position read from file: $last_position"
else
  last_position=0
  echo "No position file found, starting from position 0"
fi

current_size=$(stat -c%s "$AUDIT_LOG")
echo "Current size of audit log: $current_size"

if [ "$current_size" -gt "$last_position" ]; then
  new_entries=$(tail -c +$((last_position + 1)) "$AUDIT_LOG")
  
  if echo "$new_entries" | grep -qE "modifyTimestamp|changetype: delete|changetype: modrdn"; then
    echo "Changes detected, triggering LSC sync..."
    python3 /etc/lsc/sync_ous.py
    lsc -s x-createUsers,x-updateUsers -c x-updateUsers
    lsc -s y-createGroups,y-updateGroups -c y-createGroups
    lsc -c a-syncOU 
  fi
  
  echo "$current_size" > "$LAST_POSITION_FILE"
  echo "Updated last position to: $current_size"
else
  echo "No new entries in the audit log"
fi

echo "$(date): Script completed"
sleep 1
