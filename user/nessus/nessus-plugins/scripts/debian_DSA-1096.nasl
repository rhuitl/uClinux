# This script was automatically generated from the dsa-1096
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in webcalendar, a PHP-based
multi-user calendar, that allows a remote attacker to execute
arbitrary PHP code when register_globals is turned on.
The old stable distribution (woody) does not contain a webcalendar package.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.45-4sarge5.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.4-1
We recommend that you upgrade your webcalendar package.


Solution : http://www.debian.org/security/2006/dsa-1096
Risk factor : High';

if (description) {
 script_id(22638);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1096");
 script_cve_id("CVE-2006-2762");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1096] DSA-1096-1 webcalendar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1096-1 webcalendar");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'webcalendar', release: '', reference: '1.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webcalendar is vulnerable in Debian .\nUpgrade to webcalendar_1.0\n');
}
if (deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webcalendar is vulnerable in Debian 3.1.\nUpgrade to webcalendar_0.9.45-4sarge5\n');
}
if (deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webcalendar is vulnerable in Debian sarge.\nUpgrade to webcalendar_0.9.45-4sarge5\n');
}
if (w) { security_hole(port: 0, data: desc); }
