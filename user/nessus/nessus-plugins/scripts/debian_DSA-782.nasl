# This script was automatically generated from the dsa-782
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Henryk Plötz discovered a vulnerability in bluez-utils, tools and
daemons for Bluetooth.  Due to missing input sanitising it is possible
for an attacker to execute arbitrary commands supplied as device name
from the remote device.
The old stable distribution (woody) is not affected by this problem
since it doesn\'t contain bluez-utils packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.15-1.1.
For the unstable distribution (sid) this problem has been fixed in
version 2.19-1.
We recommend that you upgrade your bluez-utils package.


Solution : http://www.debian.org/security/2005/dsa-782
Risk factor : High';

if (description) {
 script_id(19479);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "782");
 script_cve_id("CVE-2005-2547");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA782] DSA-782-1 bluez-utils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-782-1 bluez-utils");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bluez-utils', release: '', reference: '2.19-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bluez-utils is vulnerable in Debian .\nUpgrade to bluez-utils_2.19-1\n');
}
if (deb_check(prefix: 'bluez-bcm203x', release: '3.1', reference: '2.15-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bluez-bcm203x is vulnerable in Debian 3.1.\nUpgrade to bluez-bcm203x_2.15-1.1\n');
}
if (deb_check(prefix: 'bluez-cups', release: '3.1', reference: '2.15-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bluez-cups is vulnerable in Debian 3.1.\nUpgrade to bluez-cups_2.15-1.1\n');
}
if (deb_check(prefix: 'bluez-pcmcia-support', release: '3.1', reference: '2.15-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bluez-pcmcia-support is vulnerable in Debian 3.1.\nUpgrade to bluez-pcmcia-support_2.15-1.1\n');
}
if (deb_check(prefix: 'bluez-utils', release: '3.1', reference: '2.15-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bluez-utils is vulnerable in Debian 3.1.\nUpgrade to bluez-utils_2.15-1.1\n');
}
if (deb_check(prefix: 'bluez-utils', release: '3.1', reference: '2.15-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bluez-utils is vulnerable in Debian sarge.\nUpgrade to bluez-utils_2.15-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
