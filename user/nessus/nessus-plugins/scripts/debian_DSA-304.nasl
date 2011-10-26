# This script was automatically generated from the dsa-304
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Leonard Stiles discovered that lv, a multilingual file viewer, would
read options from a configuration file in the current directory.
Because such a file could be placed there by a malicious user, and lv
configuration options can be used to execute commands, this
represented a security vulnerability.  An attacker could gain the
privileges of the user invoking lv, including root.
For the stable distribution (woody) this problem has been fixed in
version 4.49.4-7woody2.
For the old stable distribution (potato) this problem has been fixed
in version 4.49.3-4potato2.
For the unstable distribution (sid) this problem is fixed in version
4.49.5-2.
We recommend that you update your lv package.


Solution : http://www.debian.org/security/2003/dsa-304
Risk factor : High';

if (description) {
 script_id(15141);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "304");
 script_cve_id("CVE-2003-0188");
 script_bugtraq_id(7613);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA304] DSA-304-1 lv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-304-1 lv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lv', release: '2.2', reference: '4.49.3-4potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lv is vulnerable in Debian 2.2.\nUpgrade to lv_4.49.3-4potato2\n');
}
if (deb_check(prefix: 'lv', release: '3.0', reference: '4.49.5-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lv is vulnerable in Debian 3.0.\nUpgrade to lv_4.49.5-2\n');
}
if (deb_check(prefix: 'lv', release: '2.2', reference: '4.49.3-4potato2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lv is vulnerable in Debian potato.\nUpgrade to lv_4.49.3-4potato2\n');
}
if (deb_check(prefix: 'lv', release: '3.0', reference: '4.49.4-7woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lv is vulnerable in Debian woody.\nUpgrade to lv_4.49.4-7woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
