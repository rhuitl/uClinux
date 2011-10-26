# This script was automatically generated from the dsa-1083
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Mehdi Oudad and Kevin Fernandez discovered a buffer overflow in the
ktools library which is used in motor, an integrated development
environment for C, C++ and Java, which may lead local attackers to
execute arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 3.2.2-2woody1.
For the stable distribution (sarge) this problem has been fixed in
version 3.4.0-2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 3.4.0-6.
We recommend that you upgrade your motor package.


Solution : http://www.debian.org/security/2006/dsa-1083
Risk factor : High';

if (description) {
 script_id(22625);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1083");
 script_cve_id("CVE-2005-3863");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1083] DSA-1083-1 motor");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1083-1 motor");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'motor', release: '', reference: '3.4.0-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package motor is vulnerable in Debian .\nUpgrade to motor_3.4.0-6\n');
}
if (deb_check(prefix: 'motor', release: '3.0', reference: '3.2.2-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package motor is vulnerable in Debian 3.0.\nUpgrade to motor_3.2.2-2woody1\n');
}
if (deb_check(prefix: 'motor', release: '3.1', reference: '3.4.0-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package motor is vulnerable in Debian 3.1.\nUpgrade to motor_3.4.0-2sarge1\n');
}
if (deb_check(prefix: 'motor-common', release: '3.1', reference: '3.4.0-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package motor-common is vulnerable in Debian 3.1.\nUpgrade to motor-common_3.4.0-2sarge1\n');
}
if (deb_check(prefix: 'motor-fribidi', release: '3.1', reference: '3.4.0-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package motor-fribidi is vulnerable in Debian 3.1.\nUpgrade to motor-fribidi_3.4.0-2sarge1\n');
}
if (deb_check(prefix: 'motor', release: '3.1', reference: '3.4.0-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package motor is vulnerable in Debian sarge.\nUpgrade to motor_3.4.0-2sarge1\n');
}
if (deb_check(prefix: 'motor', release: '3.0', reference: '3.2.2-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package motor is vulnerable in Debian woody.\nUpgrade to motor_3.2.2-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
