# This script was automatically generated from the dsa-169
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar
discovered a problem in ht://Check\'s PHP interface.
The PHP interface displays information unchecked which was gathered
from crawled external web servers.  This could lead into a cross site
scripting attack if somebody has control over the server responses of
a remote web server which is crawled by ht://Check.
This problem has been fixed in version 1.1-1.1 for the current stable
distribution (woody) and in version 1.1-1.2 for the unstable release
(sid).  The old stable release (potato) does not contain the htcheck
package.
We recommend that you upgrade your htcheck package immediately.


Solution : http://www.debian.org/security/2002/dsa-169
Risk factor : High';

if (description) {
 script_id(15006);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "169");
 script_cve_id("CVE-2002-1195");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA169] DSA-169-1 htcheck");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-169-1 htcheck");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'htcheck', release: '3.0', reference: '1.1-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htcheck is vulnerable in Debian 3.0.\nUpgrade to htcheck_1.1-1.1\n');
}
if (deb_check(prefix: 'htcheck-php', release: '3.0', reference: '1.1-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htcheck-php is vulnerable in Debian 3.0.\nUpgrade to htcheck-php_1.1-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
