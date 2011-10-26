# This script was automatically generated from the dsa-926
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp from the Debian Security Audit Project discovered a buffer
overflow in ketm, an old school 2D-scrolling shooter game, that can be
exploited to execute arbitrary code with group games privileges.
For the old stable distribution (woody) this problem has been fixed in
version 0.0.6-7woody0.
For the stable distribution (sarge) this problem has been fixed in
version 0.0.6-17sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.0.6-17sarge1.
We recommend that you upgrade your ketm package.


Solution : http://www.debian.org/security/2005/dsa-926
Risk factor : High';

if (description) {
 script_id(22792);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "926");
 script_cve_id("CVE-2005-3535");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA926] DSA-926-2 ketm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-926-2 ketm");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ketm', release: '', reference: '0.0.6-17sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ketm is vulnerable in Debian .\nUpgrade to ketm_0.0.6-17sarge1\n');
}
if (deb_check(prefix: 'ketm', release: '3.0', reference: '0.0.6-7woody0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ketm is vulnerable in Debian 3.0.\nUpgrade to ketm_0.0.6-7woody0\n');
}
if (deb_check(prefix: 'ketm', release: '3.1', reference: '0.0.6-17sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ketm is vulnerable in Debian 3.1.\nUpgrade to ketm_0.0.6-17sarge1\n');
}
if (deb_check(prefix: 'ketm-data', release: '3.1', reference: '0.0.6-17sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ketm-data is vulnerable in Debian 3.1.\nUpgrade to ketm-data_0.0.6-17sarge1\n');
}
if (deb_check(prefix: 'ketm', release: '3.1', reference: '0.0.6-17sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ketm is vulnerable in Debian sarge.\nUpgrade to ketm_0.0.6-17sarge1\n');
}
if (deb_check(prefix: 'ketm', release: '3.0', reference: '0.0.6-7woody0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ketm is vulnerable in Debian woody.\nUpgrade to ketm_0.0.6-7woody0\n');
}
if (w) { security_hole(port: 0, data: desc); }
