# This script was automatically generated from the dsa-258
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Georgi Guninski discovered a problem in ethereal, a network traffic
analyzer.  The program contains a format string vulnerability that
could probably lead to execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 0.9.4-1woody3.
The old stable distribution (potato) does not seem to be affected
by this problem.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.9-2.
We recommend that you upgrade your ethereal packages.


Solution : http://www.debian.org/security/2003/dsa-258
Risk factor : High';

if (description) {
 script_id(15095);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "258");
 script_cve_id("CVE-2003-0081");
 script_bugtraq_id(7049);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA258] DSA-258-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-258-1 ethereal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.0.\nUpgrade to ethereal_0.9.4-1woody3\n');
}
if (deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-common is vulnerable in Debian 3.0.\nUpgrade to ethereal-common_0.9.4-1woody3\n');
}
if (deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-dev is vulnerable in Debian 3.0.\nUpgrade to ethereal-dev_0.9.4-1woody3\n');
}
if (deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tethereal is vulnerable in Debian 3.0.\nUpgrade to tethereal_0.9.4-1woody3\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.9.9-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.1.\nUpgrade to ethereal_0.9.9-2\n');
}
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian woody.\nUpgrade to ethereal_0.9.4-1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
