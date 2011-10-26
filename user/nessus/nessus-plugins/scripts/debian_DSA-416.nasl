# This script was automatically generated from the dsa-416
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in fsp, client utilities for File Service Protocol (FSP), whereby a remote user could both
escape from the FSP root directory (CVE-2003-1022), and also overflow
a fixed-length buffer to execute arbitrary code (CVE-2004-0011).
For the current stable distribution (woody) this problem has been
fixed in version 2.81.b3-3.1woody1.
For the unstable distribution, this problem is fixed in version
2.81.b18-1.
We recommend that you update your fsp package.


Solution : http://www.debian.org/security/2004/dsa-416
Risk factor : High';

if (description) {
 script_id(15253);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "416");
 script_cve_id("CVE-2003-1022", "CVE-2004-0011");
 script_bugtraq_id(9377);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA416] DSA-416-1 fsp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-416-1 fsp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fsp', release: '3.0', reference: '2.81.b3-3.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fsp is vulnerable in Debian 3.0.\nUpgrade to fsp_2.81.b3-3.1woody1\n');
}
if (deb_check(prefix: 'fspd', release: '3.0', reference: '2.81.b3-3.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fspd is vulnerable in Debian 3.0.\nUpgrade to fspd_2.81.b3-3.1woody1\n');
}
if (deb_check(prefix: 'fsp', release: '3.0', reference: '2.81.b3-3.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fsp is vulnerable in Debian woody.\nUpgrade to fsp_2.81.b3-3.1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
