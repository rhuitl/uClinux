# This script was automatically generated from the dsa-806
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Marcus Meissner discovered that the cvsbug program from gcvs, the
Graphical frontend for CVS, which serves the popular Concurrent
Versions System, uses temporary files in an insecure fashion.
For the old stable distribution (woody) this problem has been fixed in
version 1.0a7-2woody1.
For the stable distribution (sarge) this problem has been fixed in
version 1.0final-5sarge1.
The unstable distribution (sid) does not expose the cvsbug program.
We recommend that you upgrade your gcvs package.


Solution : http://www.debian.org/security/2005/dsa-806
Risk factor : High';

if (description) {
 script_id(19613);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "806");
 script_cve_id("CVE-2005-2693");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA806] DSA-806-1 gcvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-806-1 gcvs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gcvs', release: '3.0', reference: '1.0a7-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gcvs is vulnerable in Debian 3.0.\nUpgrade to gcvs_1.0a7-2woody1\n');
}
if (deb_check(prefix: 'gcvs', release: '3.1', reference: '1.0final-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gcvs is vulnerable in Debian 3.1.\nUpgrade to gcvs_1.0final-5sarge1\n');
}
if (deb_check(prefix: 'cvs', release: '3.1', reference: '1.0final-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian sarge.\nUpgrade to cvs_1.0final-5sarge1\n');
}
if (deb_check(prefix: 'cvs', release: '3.0', reference: '1.0a7-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian woody.\nUpgrade to cvs_1.0a7-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
