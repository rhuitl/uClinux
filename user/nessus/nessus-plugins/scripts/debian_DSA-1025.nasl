# This script was automatically generated from the dsa-1025
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" discovered three buffer overflow errors in the xfig
import code of dia, a diagram editor, that can lead to the execution
of arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 0.88.1-3woody1.
For the stable distribution (sarge) these problems have been fixed in
version 0.94.0-7sarge3.
For the unstable distribution (sid) these problems have been fixed in
version 0.94.0-18.
We recommend that you upgrade your dia package.


Solution : http://www.debian.org/security/2006/dsa-1025
Risk factor : High';

if (description) {
 script_id(22567);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1025");
 script_cve_id("CVE-2006-1550");
 script_bugtraq_id(15000);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1025] DSA-1025-1 dia");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1025-1 dia");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dia', release: '', reference: '0.94.0-18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia is vulnerable in Debian .\nUpgrade to dia_0.94.0-18\n');
}
if (deb_check(prefix: 'dia', release: '3.0', reference: '0.88.1-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia is vulnerable in Debian 3.0.\nUpgrade to dia_0.88.1-3woody1\n');
}
if (deb_check(prefix: 'dia-common', release: '3.0', reference: '0.88.1-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia-common is vulnerable in Debian 3.0.\nUpgrade to dia-common_0.88.1-3woody1\n');
}
if (deb_check(prefix: 'dia-gnome', release: '3.0', reference: '0.88.1-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia-gnome is vulnerable in Debian 3.0.\nUpgrade to dia-gnome_0.88.1-3woody1\n');
}
if (deb_check(prefix: 'dia', release: '3.1', reference: '0.94.0-7sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia is vulnerable in Debian 3.1.\nUpgrade to dia_0.94.0-7sarge3\n');
}
if (deb_check(prefix: 'dia-common', release: '3.1', reference: '0.94.0-7sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia-common is vulnerable in Debian 3.1.\nUpgrade to dia-common_0.94.0-7sarge3\n');
}
if (deb_check(prefix: 'dia-gnome', release: '3.1', reference: '0.94.0-7sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia-gnome is vulnerable in Debian 3.1.\nUpgrade to dia-gnome_0.94.0-7sarge3\n');
}
if (deb_check(prefix: 'dia-libs', release: '3.1', reference: '0.94.0-7sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia-libs is vulnerable in Debian 3.1.\nUpgrade to dia-libs_0.94.0-7sarge3\n');
}
if (deb_check(prefix: 'dia', release: '3.1', reference: '0.94.0-7sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia is vulnerable in Debian sarge.\nUpgrade to dia_0.94.0-7sarge3\n');
}
if (deb_check(prefix: 'dia', release: '3.0', reference: '0.88.1-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia is vulnerable in Debian woody.\nUpgrade to dia_0.88.1-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
