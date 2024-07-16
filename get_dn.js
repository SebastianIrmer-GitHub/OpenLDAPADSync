function replaceCn(dn, newCn) {
    var cnRegex = /(?:CN|cn|uid|cN)=([^,]+)/;
    var match = dn.match(cnRegex);
    if (!match) {
        throw new Error("CN not found in DN: " + dn + " and " + newCn);
    }
    
    return dn.replace(cnRegex, "cn=" + newCn);
}

function removeBaseDN(dn, baseDn, toReplace) {
    return dn.replace(baseDn, toReplace);
}

function getDnOfUser(sourceDn, newCn, baseDn, newBaseDn) {
    var updatedCn = replaceCn(sourceDn, newCn);
    return removeBaseDN(updatedCn, baseDn, newBaseDn);
}

function convertOpenLDAPToAD(openldapTimestamp) {
    // Check if the timestamp ends with 'Z'
    if (openldapTimestamp.endsWith('Z')) {
        // Find the position of the dot, if it exists
        var dotIndex = openldapTimestamp.indexOf('.');
        if (dotIndex !== -1) {
            // If a dot is found, replace everything after the dot (but before 'Z') with '000'
            return openldapTimestamp.substring(0, dotIndex + 1) + '0Z';
        } else {
            // If no dot is found, append '.000' before the 'Z'
            return openldapTimestamp.slice(0, -1) + '.0Z';
        }
    }
    // Return the original timestamp if it doesn't end with 'Z'
    return openldapTimestamp;
}

function getAccountExpiress(ldapTimestamp) {
    var TICKS_PER_MILLISECOND = 10000;
    var EPOCH_DIFFERENCE = 11644473600000;

    var baseTime = ldapTimestamp.split('.')[0];
    var milliseconds = ldapTimestamp.split('.')[1] ? parseInt(ldapTimestamp.split('.')[1].slice(0, -1)) : 0;

    var isoDateString = baseTime.slice(0, 4) + '-' + baseTime.slice(4, 6) + '-' + baseTime.slice(6, 8) +
                        'T' + baseTime.slice(8, 10) + ':' + baseTime.slice(10, 12) + ':' + baseTime.slice(12, 14) +
                        '.' + milliseconds + 'Z';

    var date = new Date(isoDateString);
    if (isNaN(date.getTime())) {
        throw new Error("Invalid date format or value");
    }

    var msSince1970 = date.getTime();
    var msSince1601 = msSince1970 + EPOCH_DIFFERENCE;

    // Ensure the number is within the safe integer range for JavaScript
    var totalIntervals = Math.floor(msSince1601 * TICKS_PER_MILLISECOND / 10000); // scaled down to avoid overflow

    return totalIntervals.toString();
}

function getAccountExpires(ldapTimestamp) {
    // Constants for conversion


    // Check if ldapTimestamp is empty or null
    if (!ldapTimestamp) {
        return "9223372036854775807";
    }

    return ldapTimestamp

}

