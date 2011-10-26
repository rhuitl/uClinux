# This script was automatically generated from the dsa-1040
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been identified in gdm, a display manager for X,
that could allow a local attacker to gain elevated privileges by
exploiting a race condition in the handling of the .ICEauthority file.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.6.0.8-1sarge2.
For the unstable distribution (sid) this problem will be fixed in
version 2.14.1-1.
We recommend that you upgrade your gdm package.


Solution : http://www.debian.org/security/2006/dsa-1040
Risk factor : High';

if (description) {
 script_id(22582);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1040");
 script_cve_id("CVE-2006-1057");
 script_bugtraq_id(17635);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1040] DSA-1040-1 gdm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1040-1 gdm");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gdm', release: '', reference: '2.14.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gdm is vulnerable in Debian .\nUpgrade to gdm_2.14.1-1\n');
}
if (deb_check(prefix: 'gdm', release: '3.1', reference: '2.6.0.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gdm is vulnerable in Debian 3.1.\nUpgrade to gdm_2.6.0.8-1sarge2\n');
}
if (deb_check(prefix: 'gdm', release: '3.1', reference: '2.6.0.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gdm is vulnerable in Debian sarge.\nUpgrade to gdm_2.6.0.8-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
