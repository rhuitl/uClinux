# This script was automatically generated from the dsa-904
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Greg Roelofs discovered and fixed several buffer overflows in pnmtopng
which is also included in netpbm, a collection of graphic conversion
utilities, that can lead to the execution of arbitrary code via a
specially crafted PNM file.
For the old stable distribution (woody) these problems have been fixed in
version 9.20-8.5.
For the stable distribution (sarge) these problems have been fixed in
version 10.0-8sarge2.
For the unstable distribution (sid) these problems will be fixed in
version 10.0-11.
We recommend that you upgrade your netpbm package.


Solution : http://www.debian.org/security/2005/dsa-904
Risk factor : High';

if (description) {
 script_id(22770);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "904");
 script_cve_id("CVE-2005-3632", "CVE-2005-3662");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA904] DSA-904-1 netpbm-free");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-904-1 netpbm-free");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'netpbm-free', release: '', reference: '10.0-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian .\nUpgrade to netpbm-free_10.0-11\n');
}
if (deb_check(prefix: 'libnetpbm9', release: '3.0', reference: '9.20-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9 is vulnerable in Debian 3.0.\nUpgrade to libnetpbm9_9.20-8.5\n');
}
if (deb_check(prefix: 'libnetpbm9-dev', release: '3.0', reference: '9.20-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9-dev is vulnerable in Debian 3.0.\nUpgrade to libnetpbm9-dev_9.20-8.5\n');
}
if (deb_check(prefix: 'netpbm', release: '3.0', reference: '9.20-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm is vulnerable in Debian 3.0.\nUpgrade to netpbm_9.20-8.5\n');
}
if (deb_check(prefix: 'libnetpbm10', release: '3.1', reference: '10.0-8sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm10 is vulnerable in Debian 3.1.\nUpgrade to libnetpbm10_10.0-8sarge2\n');
}
if (deb_check(prefix: 'libnetpbm10-dev', release: '3.1', reference: '10.0-8sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm10-dev is vulnerable in Debian 3.1.\nUpgrade to libnetpbm10-dev_10.0-8sarge2\n');
}
if (deb_check(prefix: 'libnetpbm9', release: '3.1', reference: '10.0-8sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9 is vulnerable in Debian 3.1.\nUpgrade to libnetpbm9_10.0-8sarge2\n');
}
if (deb_check(prefix: 'libnetpbm9-dev', release: '3.1', reference: '10.0-8sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9-dev is vulnerable in Debian 3.1.\nUpgrade to libnetpbm9-dev_10.0-8sarge2\n');
}
if (deb_check(prefix: 'netpbm', release: '3.1', reference: '10.0-8sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm is vulnerable in Debian 3.1.\nUpgrade to netpbm_10.0-8sarge2\n');
}
if (deb_check(prefix: 'netpbm-free', release: '3.1', reference: '10.0-8sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian sarge.\nUpgrade to netpbm-free_10.0-8sarge2\n');
}
if (deb_check(prefix: 'netpbm-free', release: '3.0', reference: '9.20-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian woody.\nUpgrade to netpbm-free_9.20-8.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
