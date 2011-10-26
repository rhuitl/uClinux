# This script was automatically generated from the dsa-878
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been identified in the pnmtopng component of the
netpbm package, a set of graphics conversion tools.  This
vulnerability could allow an attacker to execute arbitrary code as a
local user by providing a specially crafted PNM file.
The old stable distribution (woody) it not vulnerable to this problem.
For the stable distribution (sarge) this problem has been fixed in
version 10.0-8sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 10.0-10.
We recommend that you upgrade your netpbm-free packages.


Solution : http://www.debian.org/security/2005/dsa-878
Risk factor : High';

if (description) {
 script_id(22744);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "878");
 script_cve_id("CVE-2005-2978");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA878] DSA-878-1 netpbm-free");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-878-1 netpbm-free");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'netpbm-free', release: '', reference: '10.0-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian .\nUpgrade to netpbm-free_10.0-10\n');
}
if (deb_check(prefix: 'libnetpbm10', release: '3.1', reference: '10.0-8sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm10 is vulnerable in Debian 3.1.\nUpgrade to libnetpbm10_10.0-8sarge1\n');
}
if (deb_check(prefix: 'libnetpbm10-dev', release: '3.1', reference: '10.0-8sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm10-dev is vulnerable in Debian 3.1.\nUpgrade to libnetpbm10-dev_10.0-8sarge1\n');
}
if (deb_check(prefix: 'libnetpbm9', release: '3.1', reference: '10.0-8sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9 is vulnerable in Debian 3.1.\nUpgrade to libnetpbm9_10.0-8sarge1\n');
}
if (deb_check(prefix: 'libnetpbm9-dev', release: '3.1', reference: '10.0-8sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9-dev is vulnerable in Debian 3.1.\nUpgrade to libnetpbm9-dev_10.0-8sarge1\n');
}
if (deb_check(prefix: 'netpbm', release: '3.1', reference: '10.0-8sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm is vulnerable in Debian 3.1.\nUpgrade to netpbm_10.0-8sarge1\n');
}
if (deb_check(prefix: 'netpbm-free', release: '3.1', reference: '10.0-8sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian sarge.\nUpgrade to netpbm-free_10.0-8sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
