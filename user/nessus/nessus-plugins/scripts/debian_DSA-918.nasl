# This script was automatically generated from the dsa-918
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in osh, the
operator\'s shell for executing defined programs in a privileged
environment.  The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:
    Charles Stevenson discovered a bug in the substitution of
    variables that allows a local attacker to open a root shell.
    Solar Eclipse discovered a buffer overflow caused by the current
    working directory plus a filename that could be used to execute
    arbitrary code and e.g. open a root shell.
For the old stable distribution (woody) these problems have been fixed in
version 1.7-11woody2.
For the stable distribution (sarge) these problems have been fixed in
version 1.7-13sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 1.7-15, however, the package has been removed entirely.
We recommend that you upgrade your osh package.


Solution : http://www.debian.org/security/2005/dsa-918
Risk factor : High';

if (description) {
 script_id(22784);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "918");
 script_cve_id("CVE-2005-3346", "CVE-2005-3533");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA918] DSA-918-1 osh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-918-1 osh");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'osh', release: '', reference: '1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osh is vulnerable in Debian .\nUpgrade to osh_1\n');
}
if (deb_check(prefix: 'osh', release: '3.0', reference: '1.7-11woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osh is vulnerable in Debian 3.0.\nUpgrade to osh_1.7-11woody2\n');
}
if (deb_check(prefix: 'osh', release: '3.1', reference: '1.7-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osh is vulnerable in Debian 3.1.\nUpgrade to osh_1.7-13sarge1\n');
}
if (deb_check(prefix: 'osh', release: '3.1', reference: '1.7-13sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osh is vulnerable in Debian sarge.\nUpgrade to osh_1.7-13sarge1\n');
}
if (deb_check(prefix: 'osh', release: '3.0', reference: '1.7-11woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package osh is vulnerable in Debian woody.\nUpgrade to osh_1.7-11woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
