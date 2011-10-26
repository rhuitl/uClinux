# This script was automatically generated from the dsa-1021
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Max Vozeler from the Debian Audit Project discovered that pstopnm, a
converter from Postscript to the PBM, PGM and PNM formats, launches
Ghostscript in an insecure manner, which might lead to the execution
of arbitrary shell commands, when converting specially crafted Postscript
files.
For the old stable distribution (woody) this problem has been fixed in
version 9.20-8.6.
For the stable distribution (sarge) this problem has been fixed in
version 10.0-8sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 10.0-9.
We recommend that you upgrade your netpbm package.


Solution : http://www.debian.org/security/2006/dsa-1021
Risk factor : High';

if (description) {
 script_id(22563);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1021");
 script_cve_id("CVE-2005-2471");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1021] DSA-1021-1 netpbm-free");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1021-1 netpbm-free");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'netpbm-free', release: '', reference: '10.0-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian .\nUpgrade to netpbm-free_10.0-9\n');
}
if (deb_check(prefix: 'libnetpbm9', release: '3.0', reference: '9.20-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9 is vulnerable in Debian 3.0.\nUpgrade to libnetpbm9_9.20-8.6\n');
}
if (deb_check(prefix: 'libnetpbm9-dev', release: '3.0', reference: '9.20-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9-dev is vulnerable in Debian 3.0.\nUpgrade to libnetpbm9-dev_9.20-8.6\n');
}
if (deb_check(prefix: 'netpbm', release: '3.0', reference: '9.20-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm is vulnerable in Debian 3.0.\nUpgrade to netpbm_9.20-8.6\n');
}
if (deb_check(prefix: 'libnetpbm10', release: '3.1', reference: '10.0-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm10 is vulnerable in Debian 3.1.\nUpgrade to libnetpbm10_10.0-8sarge3\n');
}
if (deb_check(prefix: 'libnetpbm10-dev', release: '3.1', reference: '10.0-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm10-dev is vulnerable in Debian 3.1.\nUpgrade to libnetpbm10-dev_10.0-8sarge3\n');
}
if (deb_check(prefix: 'libnetpbm9', release: '3.1', reference: '10.0-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9 is vulnerable in Debian 3.1.\nUpgrade to libnetpbm9_10.0-8sarge3\n');
}
if (deb_check(prefix: 'libnetpbm9-dev', release: '3.1', reference: '10.0-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9-dev is vulnerable in Debian 3.1.\nUpgrade to libnetpbm9-dev_10.0-8sarge3\n');
}
if (deb_check(prefix: 'netpbm', release: '3.1', reference: '10.0-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm is vulnerable in Debian 3.1.\nUpgrade to netpbm_10.0-8sarge3\n');
}
if (deb_check(prefix: 'netpbm-free', release: '3.1', reference: '10.0-8sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian sarge.\nUpgrade to netpbm-free_10.0-8sarge3\n');
}
if (deb_check(prefix: 'netpbm-free', release: '3.0', reference: '9.20-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian woody.\nUpgrade to netpbm-free_9.20-8.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
