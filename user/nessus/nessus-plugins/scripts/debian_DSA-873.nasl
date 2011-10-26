# This script was automatically generated from the dsa-873
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A security vulnerability has been found in Net-SNMP releases that
could allow a denial of service attack against Net-SNMP agents that
have opened a stream based protocol (e.g. TCP but not UDP).  By default,
Net-SNMP does not open a TCP port.
The old stable distribution (woody) does not contain a net-snmp package.
For the stable distribution (sarge) this problem has been fixed in
version 5.1.2-6.2.
For the unstable distribution (sid) this problem has been fixed in
version 5.2.1.2-1.
We recommend that you upgrade your net-snmp package.


Solution : http://www.debian.org/security/2005/dsa-873
Risk factor : High';

if (description) {
 script_id(22739);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "873");
 script_cve_id("CVE-2005-2177");
 script_bugtraq_id(14168);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA873] DSA-873-1 net-snmp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-873-1 net-snmp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'net-snmp', release: '', reference: '5.2.1.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package net-snmp is vulnerable in Debian .\nUpgrade to net-snmp_5.2.1.2-1\n');
}
if (deb_check(prefix: 'libsnmp-base', release: '3.1', reference: '5.1.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsnmp-base is vulnerable in Debian 3.1.\nUpgrade to libsnmp-base_5.1.2-6.2\n');
}
if (deb_check(prefix: 'libsnmp-perl', release: '3.1', reference: '5.1.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsnmp-perl is vulnerable in Debian 3.1.\nUpgrade to libsnmp-perl_5.1.2-6.2\n');
}
if (deb_check(prefix: 'libsnmp5', release: '3.1', reference: '5.1.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsnmp5 is vulnerable in Debian 3.1.\nUpgrade to libsnmp5_5.1.2-6.2\n');
}
if (deb_check(prefix: 'libsnmp5-dev', release: '3.1', reference: '5.1.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsnmp5-dev is vulnerable in Debian 3.1.\nUpgrade to libsnmp5-dev_5.1.2-6.2\n');
}
if (deb_check(prefix: 'snmp', release: '3.1', reference: '5.1.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snmp is vulnerable in Debian 3.1.\nUpgrade to snmp_5.1.2-6.2\n');
}
if (deb_check(prefix: 'snmpd', release: '3.1', reference: '5.1.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snmpd is vulnerable in Debian 3.1.\nUpgrade to snmpd_5.1.2-6.2\n');
}
if (deb_check(prefix: 'tkmib', release: '3.1', reference: '5.1.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tkmib is vulnerable in Debian 3.1.\nUpgrade to tkmib_5.1.2-6.2\n');
}
if (deb_check(prefix: 'net-snmp', release: '3.1', reference: '5.1.2-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package net-snmp is vulnerable in Debian sarge.\nUpgrade to net-snmp_5.1.2-6.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
