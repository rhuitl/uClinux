# This script was automatically generated from the dsa-1172
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities have been discovered in BIND9, the Berkeley
Internet Name Domain server.  The first relates to SIG query
processing and the second relates to a condition that can trigger an
INSIST failure, both lead to a denial of service.
For the stable distribution (sarge) these problems have been fixed in
version 9.2.4-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 9.3.2-P1-1.
We recommend that you upgrade your bind9 package.


Solution : http://www.debian.org/security/2006/dsa-1172
Risk factor : High';

if (description) {
 script_id(22714);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1172");
 script_cve_id("CVE-2006-4095", "CVE-2006-4096");
 script_xref(name: "CERT", value: "697164");
 script_xref(name: "CERT", value: "915404");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1172] DSA-1172-1 bind9");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1172-1 bind9");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bind9', release: '', reference: '9.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind9 is vulnerable in Debian .\nUpgrade to bind9_9.3\n');
}
if (deb_check(prefix: 'bind9', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind9 is vulnerable in Debian 3.1.\nUpgrade to bind9_9.2.4-1sarge1\n');
}
if (deb_check(prefix: 'bind9-doc', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind9-doc is vulnerable in Debian 3.1.\nUpgrade to bind9-doc_9.2.4-1sarge1\n');
}
if (deb_check(prefix: 'bind9-host', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind9-host is vulnerable in Debian 3.1.\nUpgrade to bind9-host_9.2.4-1sarge1\n');
}
if (deb_check(prefix: 'dnsutils', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dnsutils is vulnerable in Debian 3.1.\nUpgrade to dnsutils_9.2.4-1sarge1\n');
}
if (deb_check(prefix: 'libbind-dev', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libbind-dev is vulnerable in Debian 3.1.\nUpgrade to libbind-dev_9.2.4-1sarge1\n');
}
if (deb_check(prefix: 'libdns16', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdns16 is vulnerable in Debian 3.1.\nUpgrade to libdns16_9.2.4-1sarge1\n');
}
if (deb_check(prefix: 'libisc7', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libisc7 is vulnerable in Debian 3.1.\nUpgrade to libisc7_9.2.4-1sarge1\n');
}
if (deb_check(prefix: 'libisccc0', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libisccc0 is vulnerable in Debian 3.1.\nUpgrade to libisccc0_9.2.4-1sarge1\n');
}
if (deb_check(prefix: 'libisccfg0', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libisccfg0 is vulnerable in Debian 3.1.\nUpgrade to libisccfg0_9.2.4-1sarge1\n');
}
if (deb_check(prefix: 'liblwres1', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package liblwres1 is vulnerable in Debian 3.1.\nUpgrade to liblwres1_9.2.4-1sarge1\n');
}
if (deb_check(prefix: 'lwresd', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lwresd is vulnerable in Debian 3.1.\nUpgrade to lwresd_9.2.4-1sarge1\n');
}
if (deb_check(prefix: 'bind9', release: '3.1', reference: '9.2.4-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind9 is vulnerable in Debian sarge.\nUpgrade to bind9_9.2.4-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
