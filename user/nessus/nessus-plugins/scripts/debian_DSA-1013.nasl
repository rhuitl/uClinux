# This script was automatically generated from the dsa-1013
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Will Aoki discovered that snmptrapfmt, a configurable snmp trap
handler daemon for snmpd, does not prevent overwriting existing files
when writing to a temporary log file.
For the old stable distribution (woody) this problem has been fixed in
version 1.03woody1.
For the stable distribution (sarge) this problem has been fixed in
version 1.08sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.10-1.
We recommend that you upgrade your snmptrapfmt package.


Solution : http://www.debian.org/security/2006/dsa-1013
Risk factor : High';

if (description) {
 script_id(22555);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1013");
 script_cve_id("CVE-2006-0050");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1013] DSA-1013-1 snmptrapfmt");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1013-1 snmptrapfmt");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'snmptrapfmt', release: '', reference: '1.10-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snmptrapfmt is vulnerable in Debian .\nUpgrade to snmptrapfmt_1.10-1\n');
}
if (deb_check(prefix: 'snmptrapfmt', release: '3.0', reference: '1.03woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snmptrapfmt is vulnerable in Debian 3.0.\nUpgrade to snmptrapfmt_1.03woody1\n');
}
if (deb_check(prefix: 'snmptrapfmt', release: '3.1', reference: '1.08sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snmptrapfmt is vulnerable in Debian 3.1.\nUpgrade to snmptrapfmt_1.08sarge1\n');
}
if (deb_check(prefix: 'snmptrapfmt', release: '3.1', reference: '1.08sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snmptrapfmt is vulnerable in Debian sarge.\nUpgrade to snmptrapfmt_1.08sarge1\n');
}
if (deb_check(prefix: 'snmptrapfmt', release: '3.0', reference: '1.03woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snmptrapfmt is vulnerable in Debian woody.\nUpgrade to snmptrapfmt_1.03woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
