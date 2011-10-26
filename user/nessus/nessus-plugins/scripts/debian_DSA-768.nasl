# This script was automatically generated from the dsa-768
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A cross-site scripting vulnerability has been detected in phpBB2, a
fully featured and skinneable flat webforum software, that allows
remote attackers to inject arbitrary web script or HTML via nested
tags.
The old stable distribution (woody) does not contain phpbb2.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.13-6sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.13-6sarge1.
We recommend that you upgrade your phpbb2 packages.


Solution : http://www.debian.org/security/2005/dsa-768
Risk factor : High';

if (description) {
 script_id(19317);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "768");
 script_cve_id("CVE-2005-2161");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA768] DSA-768-1 phpbb2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-768-1 phpbb2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'phpbb2', release: '', reference: '2.0.13-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2 is vulnerable in Debian .\nUpgrade to phpbb2_2.0.13-6sarge1\n');
}
if (deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2 is vulnerable in Debian 3.1.\nUpgrade to phpbb2_2.0.13-6sarge1\n');
}
if (deb_check(prefix: 'phpbb2-conf-mysql', release: '3.1', reference: '2.0.13-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2-conf-mysql is vulnerable in Debian 3.1.\nUpgrade to phpbb2-conf-mysql_2.0.13-6sarge1\n');
}
if (deb_check(prefix: 'phpbb2-languages', release: '3.1', reference: '2.0.13-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2-languages is vulnerable in Debian 3.1.\nUpgrade to phpbb2-languages_2.0.13-6sarge1\n');
}
if (deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2 is vulnerable in Debian sarge.\nUpgrade to phpbb2_2.0.13-6sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
