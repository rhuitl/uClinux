# This script was automatically generated from the dsa-585
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in the shadow suite which provides
programs like chfn and chsh.  It is possible for a user, who is logged
in but has an expired password to alter his account information with
chfn or chsh without having to change the password.  The problem was
originally thought to be more severe.
For the stable distribution (woody) this problem has been fixed in
version 20000902-12woody1.
For the unstable distribution (sid) this problem has been fixed in
version 4.0.3-30.3.
We recommend that you upgrade your passwd package (from the shadow
suite).


Solution : http://www.debian.org/security/2004/dsa-585
Risk factor : High';

if (description) {
 script_id(15683);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "585");
 script_cve_id("CVE-2004-1001");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA585] DSA-585-1 shadow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-585-1 shadow");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'login', release: '3.0', reference: '20000902-12woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package login is vulnerable in Debian 3.0.\nUpgrade to login_20000902-12woody1\n');
}
if (deb_check(prefix: 'passwd', release: '3.0', reference: '20000902-12woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package passwd is vulnerable in Debian 3.0.\nUpgrade to passwd_20000902-12woody1\n');
}
if (deb_check(prefix: 'shadow', release: '3.1', reference: '4.0.3-30.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package shadow is vulnerable in Debian 3.1.\nUpgrade to shadow_4.0.3-30.3\n');
}
if (deb_check(prefix: 'shadow', release: '3.0', reference: '20000902-12woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package shadow is vulnerable in Debian woody.\nUpgrade to shadow_20000902-12woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
