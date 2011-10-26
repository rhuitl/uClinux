# This script was automatically generated from the dsa-604
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" discovered a buffer overflow condition in hpsockd, the
socks server written at Hewlett-Packard.  An exploit could cause the
program to crash or may have worse effect.
For the stable distribution (woody) this problem has been fixed in
version 0.6.woody1.
For the unstable distribution (sid) this problem has been fixed in
version 0.14.
We recommend that you upgrade your hpsockd package.


Solution : http://www.debian.org/security/2004/dsa-604
Risk factor : High';

if (description) {
 script_id(15899);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "604");
 script_cve_id("CVE-2004-0993");
 script_bugtraq_id(11800);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA604] DSA-604-1 hpsockd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-604-1 hpsockd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hpsockd', release: '3.0', reference: '0.6.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hpsockd is vulnerable in Debian 3.0.\nUpgrade to hpsockd_0.6.woody1\n');
}
if (deb_check(prefix: 'hpsockd', release: '3.1', reference: '0.14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hpsockd is vulnerable in Debian 3.1.\nUpgrade to hpsockd_0.14\n');
}
if (deb_check(prefix: 'hpsockd', release: '3.0', reference: '0.6.woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hpsockd is vulnerable in Debian woody.\nUpgrade to hpsockd_0.6.woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
