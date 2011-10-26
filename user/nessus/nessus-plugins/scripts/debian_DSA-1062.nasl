# This script was automatically generated from the dsa-1062
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Sven Dreyer discovered that KPhone, a Voice over IP client for KDE,
creates a configuration file world-readable, which could leak sensitive
information like SIP passwords.
The old stable distribution (woody) doesn\'t contain kphone packages.
For the stable distribution (sarge) this problem has been fixed in
version 4.1.0-2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 4.2-6.
We recommend that you upgrade your kphone package. If your current kphonerc
has too lax permissions, you\'ll need to reset them manually.


Solution : http://www.debian.org/security/2006/dsa-1062
Risk factor : High';

if (description) {
 script_id(22604);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1062");
 script_cve_id("CVE-2006-2442");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1062] DSA-1062-1 kphone");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1062-1 kphone");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kphone', release: '', reference: '4.2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kphone is vulnerable in Debian .\nUpgrade to kphone_4.2-6\n');
}
if (deb_check(prefix: 'kphone', release: '3.1', reference: '4.1.0-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kphone is vulnerable in Debian 3.1.\nUpgrade to kphone_4.1.0-2sarge1\n');
}
if (deb_check(prefix: 'kphone', release: '3.1', reference: '4.1.0-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kphone is vulnerable in Debian sarge.\nUpgrade to kphone_4.1.0-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
