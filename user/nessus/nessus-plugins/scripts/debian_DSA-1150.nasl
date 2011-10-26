# This script was automatically generated from the dsa-1150
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A bug has been discovered in several packages that execute the
setuid() system call without checking for success when trying to drop
privileges, which may fail with some PAM configurations.
For the stable distribution (sarge) this problem has been fixed in
version 4.0.3-31sarge8.
For the unstable distribution (sid) this problem has been fixed in
version 4.0.17-2.
We recommend that you upgrade your passwd package.


Solution : http://www.debian.org/security/2006/dsa-1150
Risk factor : High';

if (description) {
 script_id(22692);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1150");
 script_cve_id("CVE-2006-3378");
 script_bugtraq_id(18850);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1150] DSA-1150-1 shadow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1150-1 shadow");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'shadow', release: '', reference: '4.0.17-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package shadow is vulnerable in Debian .\nUpgrade to shadow_4.0.17-2\n');
}
if (deb_check(prefix: 'login', release: '3.1', reference: '4.0.3-31sarge8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package login is vulnerable in Debian 3.1.\nUpgrade to login_4.0.3-31sarge8\n');
}
if (deb_check(prefix: 'passwd', release: '3.1', reference: '4.0.3-31sarge8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package passwd is vulnerable in Debian 3.1.\nUpgrade to passwd_4.0.3-31sarge8\n');
}
if (deb_check(prefix: 'shadow', release: '3.1', reference: '4.0.3-31sarge8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package shadow is vulnerable in Debian sarge.\nUpgrade to shadow_4.0.3-31sarge8\n');
}
if (w) { security_hole(port: 0, data: desc); }
