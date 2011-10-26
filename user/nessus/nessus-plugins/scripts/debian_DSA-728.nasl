# This script was automatically generated from the dsa-728
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
This advisory does only cover updated packages for Debian 3.0
alias woody. For reference below is the original advisory text:
Two bugs have been discovered in qpopper, an enhanced Post Office
Protocol (POP3) server.  The Common Vulnerability and Exposures
project identifies the following problems:
    Jens Steube discovered that while processing local files owned or
    provided by a normal user privileges weren\'t dropped, which could
    lead to the overwriting or creation of arbitrary files as root.
    The upstream developers noticed that qpopper could be tricked to
    creating group- or world-writable files.
For the stable distribution (woody) these problems have been fixed in
version 4.0.4-2.woody.5.
For the testing distribution (sarge) these problems have been fixed in
version 4.0.5-4sarge1.
For the unstable distribution (sid) these problems will be fixed in
version 4.0.5-4sarge1.
We recommend that you upgrade your qpopper package.


Solution : http://www.debian.org/security/2005/dsa-728
Risk factor : High';

if (description) {
 script_id(18515);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "728");
 script_cve_id("CVE-2005-1151", "CVE-2005-1152");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA728] DSA-728-2 qpopper");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-728-2 qpopper");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'qpopper', release: '', reference: '4.0.5-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qpopper is vulnerable in Debian .\nUpgrade to qpopper_4.0.5-4sarge1\n');
}
if (deb_check(prefix: 'qpopper', release: '3.0', reference: '4.0.4-2.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qpopper is vulnerable in Debian 3.0.\nUpgrade to qpopper_4.0.4-2.woody.5\n');
}
if (deb_check(prefix: 'qpopper-drac', release: '3.0', reference: '4.0.4-2.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qpopper-drac is vulnerable in Debian 3.0.\nUpgrade to qpopper-drac_4.0.4-2.woody.5\n');
}
if (deb_check(prefix: 'qpopper', release: '3.1', reference: '4.0.5-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qpopper is vulnerable in Debian 3.1.\nUpgrade to qpopper_4.0.5-4sarge1\n');
}
if (deb_check(prefix: 'qpopper-drac', release: '3.1', reference: '4.0.5-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qpopper-drac is vulnerable in Debian 3.1.\nUpgrade to qpopper-drac_4.0.5-4sarge1\n');
}
if (deb_check(prefix: 'qpopper', release: '3.1', reference: '4.0.5-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qpopper is vulnerable in Debian sarge.\nUpgrade to qpopper_4.0.5-4sarge1\n');
}
if (deb_check(prefix: 'qpopper', release: '3.0', reference: '4.0.4-2.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qpopper is vulnerable in Debian woody.\nUpgrade to qpopper_4.0.4-2.woody.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
