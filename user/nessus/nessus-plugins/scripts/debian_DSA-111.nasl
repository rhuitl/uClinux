# This script was automatically generated from the dsa-111
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The Secure Programming Group of the Oulu University did a study on
SNMP implementations and uncovered multiple problems which can
cause problems ranging from Denial of Service attacks to remote
exploits.
New UCD-SNMP packages have been prepared to fix these problems
as well as a few others. The complete list of fixed problems is:
(thanks to Caldera for most of the work on those patches)
The new version is 4.1.1-2.1 and we recommend you upgrade your
snmp packages immediately.


Solution : http://www.debian.org/security/2002/dsa-111
Risk factor : High';

if (description) {
 script_id(14948);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "111");
 script_cve_id("CVE-2002-012", "CVE-2002-013");
 script_xref(name: "CERT", value: "107186");
 script_xref(name: "CERT", value: "854306");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA111] DSA-111-1 ucd-snmp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-111-1 ucd-snmp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libsnmp4.1', release: '2.2', reference: '4.1.1-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsnmp4.1 is vulnerable in Debian 2.2.\nUpgrade to libsnmp4.1_4.1.1-2.2\n');
}
if (deb_check(prefix: 'libsnmp4.1-dev', release: '2.2', reference: '4.1.1-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsnmp4.1-dev is vulnerable in Debian 2.2.\nUpgrade to libsnmp4.1-dev_4.1.1-2.2\n');
}
if (deb_check(prefix: 'snmp', release: '2.2', reference: '4.1.1-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snmp is vulnerable in Debian 2.2.\nUpgrade to snmp_4.1.1-2.2\n');
}
if (deb_check(prefix: 'snmpd', release: '2.2', reference: '4.1.1-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package snmpd is vulnerable in Debian 2.2.\nUpgrade to snmpd_4.1.1-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
