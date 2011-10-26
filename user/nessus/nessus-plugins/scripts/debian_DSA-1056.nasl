# This script was automatically generated from the dsa-1056
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
David Maciejak noticed that webcalendar, a PHP-based multi-user
calendar, returns different error messages on login attempts for an
invalid password and a non-existing user, allowing remote attackers to
gain information about valid usernames.
The old stable distribution (woody) does not contain a webcalendar package.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.45-4sarge4.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your webcalendar package.


Solution : http://www.debian.org/security/2006/dsa-1056
Risk factor : High';

if (description) {
 script_id(22598);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1056");
 script_cve_id("CVE-2006-2247");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1056] DSA-1056-1 webcalendar");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1056-1 webcalendar");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webcalendar is vulnerable in Debian 3.1.\nUpgrade to webcalendar_0.9.45-4sarge4\n');
}
if (deb_check(prefix: 'webcalendar', release: '3.1', reference: '0.9.45-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package webcalendar is vulnerable in Debian sarge.\nUpgrade to webcalendar_0.9.45-4sarge4\n');
}
if (w) { security_hole(port: 0, data: desc); }
