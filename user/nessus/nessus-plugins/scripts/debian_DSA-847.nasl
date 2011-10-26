# This script was automatically generated from the dsa-847
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Joxean Koret discovered that the Python SVG import plugin in dia, a
vector-oriented diagram editor, does not properly sanitise data read
from an SVG file and is hence vulnerable to execute arbitrary Python
code.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.94.0-7sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.94.0-15.
We recommend that you upgrade your dia package.


Solution : http://www.debian.org/security/2005/dsa-847
Risk factor : High';

if (description) {
 script_id(19955);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "847");
 script_cve_id("CVE-2005-2966");
 script_bugtraq_id(15000);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA847] DSA-847-1 dia");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-847-1 dia");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dia', release: '', reference: '0.94.0-15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia is vulnerable in Debian .\nUpgrade to dia_0.94.0-15\n');
}
if (deb_check(prefix: 'dia', release: '3.1', reference: '0.94.0-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia is vulnerable in Debian 3.1.\nUpgrade to dia_0.94.0-7sarge1\n');
}
if (deb_check(prefix: 'dia-common', release: '3.1', reference: '0.94.0-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia-common is vulnerable in Debian 3.1.\nUpgrade to dia-common_0.94.0-7sarge1\n');
}
if (deb_check(prefix: 'dia-gnome', release: '3.1', reference: '0.94.0-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia-gnome is vulnerable in Debian 3.1.\nUpgrade to dia-gnome_0.94.0-7sarge1\n');
}
if (deb_check(prefix: 'dia-libs', release: '3.1', reference: '0.94.0-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia-libs is vulnerable in Debian 3.1.\nUpgrade to dia-libs_0.94.0-7sarge1\n');
}
if (deb_check(prefix: 'dia', release: '3.1', reference: '0.94.0-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dia is vulnerable in Debian sarge.\nUpgrade to dia_0.94.0-7sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
