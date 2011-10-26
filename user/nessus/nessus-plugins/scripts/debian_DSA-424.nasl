# This script was automatically generated from the dsa-424
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in Midnight Commander, a file manager,
whereby a malicious archive (such as a .tar file) could cause
arbitrary code to be executed if opened by Midnight Commander.
For the current stable distribution (woody) this problem has been
fixed in version 4.5.55-1.2woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1:4.6.0-4.6.1-pre1-1.
We recommend that you update your mc package.


Solution : http://www.debian.org/security/2004/dsa-424
Risk factor : High';

if (description) {
 script_id(15261);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "424");
 script_cve_id("CVE-2003-1023");
 script_bugtraq_id(8658);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA424] DSA-424-1 mc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-424-1 mc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gmc', release: '3.0', reference: '4.5.55-1.2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gmc is vulnerable in Debian 3.0.\nUpgrade to gmc_4.5.55-1.2woody2\n');
}
if (deb_check(prefix: 'mc', release: '3.0', reference: '4.5.55-1.2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc is vulnerable in Debian 3.0.\nUpgrade to mc_4.5.55-1.2woody2\n');
}
if (deb_check(prefix: 'mc-common', release: '3.0', reference: '4.5.55-1.2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc-common is vulnerable in Debian 3.0.\nUpgrade to mc-common_4.5.55-1.2woody2\n');
}
if (deb_check(prefix: 'mc', release: '3.1', reference: '4.6.0-4.6.1-pre1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc is vulnerable in Debian 3.1.\nUpgrade to mc_4.6.0-4.6.1-pre1-1\n');
}
if (deb_check(prefix: 'mc', release: '3.0', reference: '4.5.55-1.2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc is vulnerable in Debian woody.\nUpgrade to mc_4.5.55-1.2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
