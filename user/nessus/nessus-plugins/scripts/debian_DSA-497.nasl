# This script was automatically generated from the dsa-497
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jacub Jelinek discovered several vulnerabilities in the Midnight
Commander, a powerful file manager for GNU/Linux systems.  The
problems were classified as follows:
CVE-2004-0226 Buffer overflows
CVE-2004-0231 Insecure temporary file and directory creations
CVE-2004-0232 Format string problems
For the stable distribution (woody) this problem has been fixed in
version 4.5.55-1.2woody3.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your mc packages.


Solution : http://www.debian.org/security/2004/dsa-497
Risk factor : High';

if (description) {
 script_id(15334);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "497");
 script_cve_id("CVE-2004-0226", "CVE-2004-0231", "CVE-2004-0232");
 script_bugtraq_id(10242);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA497] DSA-497-1 mc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-497-1 mc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gmc', release: '3.0', reference: '4.5.55-1.2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gmc is vulnerable in Debian 3.0.\nUpgrade to gmc_4.5.55-1.2woody3\n');
}
if (deb_check(prefix: 'mc', release: '3.0', reference: '4.5.55-1.2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc is vulnerable in Debian 3.0.\nUpgrade to mc_4.5.55-1.2woody3\n');
}
if (deb_check(prefix: 'mc-common', release: '3.0', reference: '4.5.55-1.2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc-common is vulnerable in Debian 3.0.\nUpgrade to mc-common_4.5.55-1.2woody3\n');
}
if (deb_check(prefix: 'mc', release: '3.0', reference: '4.5.55-1.2woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc is vulnerable in Debian woody.\nUpgrade to mc_4.5.55-1.2woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
