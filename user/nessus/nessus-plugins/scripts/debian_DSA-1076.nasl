# This script was automatically generated from the dsa-1076
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Michal Zalewski discovered that lynx, the popular text-mode WWW
Browser, is not able to grok invalid HTML including a TEXTAREA tag
with a large COLS value and a large tag name in an element that is not
terminated, and loops forever trying to render the broken HTML.
For the old stable distribution (woody) this problem has been fixed in
version 2.8.4.1b-3.4.
For the stable distribution (sarge) this problem has been fixed in
version 2.8.5-2sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 2.8.5-2sarge2.
We recommend that you upgrade your lynx package.


Solution : http://www.debian.org/security/2006/dsa-1076
Risk factor : High';

if (description) {
 script_id(22618);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1076");
 script_cve_id("CVE-2004-1617");
 script_bugtraq_id(11443);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1076] DSA-1076-1 lynx");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1076-1 lynx");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lynx', release: '', reference: '2.8.5-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx is vulnerable in Debian .\nUpgrade to lynx_2.8.5-2sarge2\n');
}
if (deb_check(prefix: 'lynx', release: '3.0', reference: '2.8.4.1b-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx is vulnerable in Debian 3.0.\nUpgrade to lynx_2.8.4.1b-3.4\n');
}
if (deb_check(prefix: 'lynx', release: '3.1', reference: '2.8.5-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx is vulnerable in Debian 3.1.\nUpgrade to lynx_2.8.5-2sarge2\n');
}
if (deb_check(prefix: 'lynx', release: '3.1', reference: '2.8.5-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx is vulnerable in Debian sarge.\nUpgrade to lynx_2.8.5-2sarge2\n');
}
if (deb_check(prefix: 'lynx', release: '3.0', reference: '2.8.4.1b-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lynx is vulnerable in Debian woody.\nUpgrade to lynx_2.8.4.1b-3.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
