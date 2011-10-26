# This script was automatically generated from the dsa-263
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Al Viro and Alan Cox discovered several maths overflow errors in
NetPBM, a set of graphics conversion tools.  These programs are not
installed setuid root but are often installed to prepare data for
processing.  These vulnerabilities may allow remote attackers to cause
a denial of service or execute arbitrary code.
For the stable distribution (woody) this problem has been
fixed in version 9.20-8.2.
The old stable distribution (potato) does not seem to be affected
by this problem.
For the unstable distribution (sid) this problem has been
fixed in version 9.20-9.
We recommend that you upgrade your netpbm package.


Solution : http://www.debian.org/security/2003/dsa-263
Risk factor : High';

if (description) {
 script_id(15100);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "263");
 script_cve_id("CVE-2003-0146");
 script_xref(name: "CERT", value: "378049");
 script_xref(name: "CERT", value: "630433");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA263] DSA-263-1 netpbm-free");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-263-1 netpbm-free");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libnetpbm9', release: '3.0', reference: '9.20-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9 is vulnerable in Debian 3.0.\nUpgrade to libnetpbm9_9.20-8.2\n');
}
if (deb_check(prefix: 'libnetpbm9-dev', release: '3.0', reference: '9.20-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnetpbm9-dev is vulnerable in Debian 3.0.\nUpgrade to libnetpbm9-dev_9.20-8.2\n');
}
if (deb_check(prefix: 'netpbm', release: '3.0', reference: '9.20-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm is vulnerable in Debian 3.0.\nUpgrade to netpbm_9.20-8.2\n');
}
if (deb_check(prefix: 'netpbm-free', release: '3.1', reference: '9.20-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian 3.1.\nUpgrade to netpbm-free_9.20-9\n');
}
if (deb_check(prefix: 'netpbm-free', release: '3.0', reference: '9.20-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netpbm-free is vulnerable in Debian woody.\nUpgrade to netpbm-free_9.20-8.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
