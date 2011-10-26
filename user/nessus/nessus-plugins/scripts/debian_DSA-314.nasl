# This script was automatically generated from the dsa-314
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Rick Patel discovered that atftpd is vulnerable to a buffer overflow
when a long filename is sent to the server.  An attacker could exploit
this bug remotely to execute arbitrary code on the server.
For the stable distribution (woody), this problem has been fixed in
version 0.6.1.1.0woody1.
The old stable distribution (potato) does not contain an atftp
package.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your atftp package.


Solution : http://www.debian.org/security/2003/dsa-314
Risk factor : High';

if (description) {
 script_id(15151);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "314");
 script_cve_id("CVE-2003-0380");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA314] DSA-314-1 atftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-314-1 atftp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'atftp', release: '3.0', reference: '0.6.0woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package atftp is vulnerable in Debian 3.0.\nUpgrade to atftp_0.6.0woody1\n');
}
if (deb_check(prefix: 'atftpd', release: '3.0', reference: '0.6.0woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package atftpd is vulnerable in Debian 3.0.\nUpgrade to atftpd_0.6.0woody1\n');
}
if (deb_check(prefix: 'atftp', release: '3.0', reference: '0.6.1.1.0woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package atftp is vulnerable in Debian woody.\nUpgrade to atftp_0.6.1.1.0woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
