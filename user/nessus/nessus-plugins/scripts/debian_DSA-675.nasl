# This script was automatically generated from the dsa-675
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Erik Sjölund discovered that hztty, a converter for GB, Big5 and zW/HZ
Chinese encodings in a tty session, can be triggered to execute
arbitrary commands with group utmp privileges.
For the stable distribution (woody) this problem has been fixed in
version 2.0-5.2woody2.
For the unstable distribution (sid) this problem has been fixed in
version 2.0-6.1.
We recommend that you upgrade your hztty package.


Solution : http://www.debian.org/security/2005/dsa-675
Risk factor : High';

if (description) {
 script_id(16365);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "675");
 script_cve_id("CVE-2005-0019");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA675] DSA-675-1 hztty");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-675-1 hztty");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hztty', release: '3.0', reference: '2.0-5.2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hztty is vulnerable in Debian 3.0.\nUpgrade to hztty_2.0-5.2woody2\n');
}
if (deb_check(prefix: 'hztty', release: '3.1', reference: '2.0-6.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hztty is vulnerable in Debian 3.1.\nUpgrade to hztty_2.0-6.1\n');
}
if (deb_check(prefix: 'hztty', release: '3.0', reference: '2.0-5.2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hztty is vulnerable in Debian woody.\nUpgrade to hztty_2.0-5.2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
