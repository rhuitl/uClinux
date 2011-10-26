# This script was automatically generated from the dsa-289
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Sam Hocevar discovered a security problem in rinetd, an IP connection
redirection server.  When the connection list is full, rinetd resizes
the list in order to store the new incoming connection.  However, this
is done improperly, resulting in a denial of service and potentially
execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 0.61-1.1.
For the old stable distribution (potato) this problem has been
fixed in version 0.52-2.1.
For the unstable distribution (sid) this problem has been fixed in
version 0.61-2
We recommend that you upgrade your rinetd package.


Solution : http://www.debian.org/security/2003/dsa-289
Risk factor : High';

if (description) {
 script_id(15126);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "289");
 script_cve_id("CVE-2003-0212");
 script_bugtraq_id(7377);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA289] DSA-289-1 rinetd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-289-1 rinetd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'rinetd', release: '2.2', reference: '0.52-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rinetd is vulnerable in Debian 2.2.\nUpgrade to rinetd_0.52-2.1\n');
}
if (deb_check(prefix: 'rinetd', release: '3.0', reference: '0.61-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rinetd is vulnerable in Debian 3.0.\nUpgrade to rinetd_0.61-1.1\n');
}
if (deb_check(prefix: 'rinetd', release: '3.1', reference: '0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rinetd is vulnerable in Debian 3.1.\nUpgrade to rinetd_0\n');
}
if (deb_check(prefix: 'rinetd', release: '2.2', reference: '0.52-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rinetd is vulnerable in Debian potato.\nUpgrade to rinetd_0.52-2.1\n');
}
if (deb_check(prefix: 'rinetd', release: '3.0', reference: '0.61-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rinetd is vulnerable in Debian woody.\nUpgrade to rinetd_0.61-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
