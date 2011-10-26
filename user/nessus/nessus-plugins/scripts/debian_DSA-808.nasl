# This script was automatically generated from the dsa-808
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Yutaka Oiwa and Hiromitsu Takagi discovered a Cross-Site Request
Forgery (CSRF) vulnerability in tdiary, a new generation weblog that
can be exploited by remote attackers to alter the users information.
The old stable distribution (woody) does not contain tdiary packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.1-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.2-1.
We recommend that you upgrade your tdiary packages.


Solution : http://www.debian.org/security/2005/dsa-808
Risk factor : High';

if (description) {
 script_id(19683);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "808");
 script_cve_id("CVE-2005-2411");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA808] DSA-808-1 tdiary");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-808-1 tdiary");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tdiary', release: '', reference: '2.0.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tdiary is vulnerable in Debian .\nUpgrade to tdiary_2.0.2-1\n');
}
if (deb_check(prefix: 'tdiary', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tdiary is vulnerable in Debian 3.1.\nUpgrade to tdiary_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'tdiary-contrib', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tdiary-contrib is vulnerable in Debian 3.1.\nUpgrade to tdiary-contrib_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'tdiary-mode', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tdiary-mode is vulnerable in Debian 3.1.\nUpgrade to tdiary-mode_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'tdiary-plugin', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tdiary-plugin is vulnerable in Debian 3.1.\nUpgrade to tdiary-plugin_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'tdiary-theme', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tdiary-theme is vulnerable in Debian 3.1.\nUpgrade to tdiary-theme_2.0.1-1sarge1\n');
}
if (deb_check(prefix: 'tdiary', release: '3.1', reference: '2.0.1-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tdiary is vulnerable in Debian sarge.\nUpgrade to tdiary_2.0.1-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
