# This script was automatically generated from the dsa-1115
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Evgeny Legerov discovered that gnupg, the GNU privacy guard, a free
PGP replacement contains an integer overflow that can cause a
segmentation fault and possibly overwrite memory via a large user ID
string.
For the stable distribution (sarge) this problem has been fixed in
version 1.4.1-1.sarge4 of GnuPG and in version 1.9.15-6sarge1 of GnuPG2.
For the unstable distribution (sid) this problem has been fixed in
version 1.4.3-2 of GnuPG, a fix for GnuPG2 is pending.
We recommend that you upgrade your gnupg package.


Solution : http://www.debian.org/security/2006/dsa-1115
Risk factor : High';

if (description) {
 script_id(22657);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1115");
 script_cve_id("CVE-2006-3082");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1115] DSA-1115-1 gnupg2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1115-1 gnupg2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnupg2', release: '', reference: '1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg2 is vulnerable in Debian .\nUpgrade to gnupg2_1.4\n');
}
if (deb_check(prefix: 'gnupg-agent', release: '3.1', reference: '1.9.15-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg-agent is vulnerable in Debian 3.1.\nUpgrade to gnupg-agent_1.9.15-6sarge1\n');
}
if (deb_check(prefix: 'gnupg2', release: '3.1', reference: '1.9.15-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg2 is vulnerable in Debian 3.1.\nUpgrade to gnupg2_1.9.15-6sarge1\n');
}
if (deb_check(prefix: 'gpgsm', release: '3.1', reference: '1.9.15-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpgsm is vulnerable in Debian 3.1.\nUpgrade to gpgsm_1.9.15-6sarge1\n');
}
if (deb_check(prefix: 'gnupg2', release: '3.1', reference: '1.4.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnupg2 is vulnerable in Debian sarge.\nUpgrade to gnupg2_1.4.1-1\n');
}
if (w) { security_hole(port: 0, data: desc); }
