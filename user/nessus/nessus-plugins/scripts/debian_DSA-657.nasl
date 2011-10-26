# This script was automatically generated from the dsa-657
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A heap overflow has been discovered in the DVD subpicture decoder of
xine-lib.  An attacker could cause arbitrary code to be executed on
the victims host by supplying a malicious MPEG.  By tricking users to
view a malicious network stream, this is remotely exploitable.
For the stable distribution (woody) this problem has been fixed in
version 0.9.8-2woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1-rc6a-1.
We recommend that you upgrade your libxine packages.


Solution : http://www.debian.org/security/2005/dsa-657
Risk factor : High';

if (description) {
 script_id(16248);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "657");
 script_cve_id("CVE-2004-1379");
 script_bugtraq_id(11205);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA657] DSA-657-1 xine-lib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-657-1 xine-lib");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libxine-dev', release: '3.0', reference: '0.9.8-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxine-dev is vulnerable in Debian 3.0.\nUpgrade to libxine-dev_0.9.8-2woody3\n');
}
if (deb_check(prefix: 'libxine0', release: '3.0', reference: '0.9.8-2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libxine0 is vulnerable in Debian 3.0.\nUpgrade to libxine0_0.9.8-2woody3\n');
}
if (deb_check(prefix: 'xine-lib', release: '3.1', reference: '1-rc6a-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xine-lib is vulnerable in Debian 3.1.\nUpgrade to xine-lib_1-rc6a-1\n');
}
if (deb_check(prefix: 'xine-lib', release: '3.0', reference: '0.9.8-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xine-lib is vulnerable in Debian woody.\nUpgrade to xine-lib_0.9.8-2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
