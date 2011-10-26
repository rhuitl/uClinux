# This script was automatically generated from the dsa-461
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Leon Juranic discovered a buffer overflow related to the
getpass(3) library function in
calife, a program which provides super user privileges to specific
users.  A local attacker could potentially
exploit this vulnerability, given knowledge of a local user\'s password
and the presence of at least one entry in /etc/calife.auth, to execute
arbitrary code with root privileges.
For the current stable distribution (woody) this problem has been
fixed in version 2.8.4c-1woody1.
For the unstable distribution (sid) this problem has been fixed in
version 2.8.6-1.
We recommend that you update your calife package.


Solution : http://www.debian.org/security/2004/dsa-461
Risk factor : High';

if (description) {
 script_id(15298);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "461");
 script_cve_id("CVE-2004-0188");
 script_bugtraq_id(9756);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA461] DSA-461-1 calife");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-461-1 calife");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'calife', release: '3.0', reference: '2.8.4c-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package calife is vulnerable in Debian 3.0.\nUpgrade to calife_2.8.4c-1woody1\n');
}
if (deb_check(prefix: 'calife', release: '3.1', reference: '2.8.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package calife is vulnerable in Debian 3.1.\nUpgrade to calife_2.8.6-1\n');
}
if (deb_check(prefix: 'calife', release: '3.0', reference: '2.8.4c-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package calife is vulnerable in Debian woody.\nUpgrade to calife_2.8.4c-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
