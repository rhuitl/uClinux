# This script was automatically generated from the dsa-844
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability in mod_auth_shadow, an Apache module that lets users
perform HTTP authentication against /etc/shadow, has been discovered.
The module runs for all locations that use the \'require group\'
directive which would bypass access restrictions controlled by another
authorisation mechanism, such as AuthGroupFile file, if the username
is listed in the password file and in the gshadow file in the proper
group and the supplied password matches against the one in the shadow
file.
This update requires an explicit "AuthShadow on" statement if website
authentication should be checked against /etc/shadow.
For the old stable distribution (woody) this problem has been fixed in
version 1.3-3.1woody.2.
For the stable distribution (sarge) this problem has been fixed in
version 1.4-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.4-2.
We recommend that you upgrade your libapache-mod-auth-shadow package.


Solution : http://www.debian.org/security/2005/dsa-844
Risk factor : High';

if (description) {
 script_id(19848);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "844");
 script_cve_id("CVE-2005-2963");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA844] DSA-844-1 mod-auth-shadow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-844-1 mod-auth-shadow");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mod-auth-shadow', release: '', reference: '1.4-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mod-auth-shadow is vulnerable in Debian .\nUpgrade to mod-auth-shadow_1.4-2\n');
}
if (deb_check(prefix: 'libapache-mod-auth-shadow', release: '3.0', reference: '1.3-3.1woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-auth-shadow is vulnerable in Debian 3.0.\nUpgrade to libapache-mod-auth-shadow_1.3-3.1woody.2\n');
}
if (deb_check(prefix: 'libapache-mod-auth-shadow', release: '3.1', reference: '1.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-auth-shadow is vulnerable in Debian 3.1.\nUpgrade to libapache-mod-auth-shadow_1.4-1sarge1\n');
}
if (deb_check(prefix: 'mod-auth-shadow', release: '3.1', reference: '1.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mod-auth-shadow is vulnerable in Debian sarge.\nUpgrade to mod-auth-shadow_1.4-1sarge1\n');
}
if (deb_check(prefix: 'mod-auth-shadow', release: '3.0', reference: '1.3-3.1woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mod-auth-shadow is vulnerable in Debian woody.\nUpgrade to mod-auth-shadow_1.3-3.1woody.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
