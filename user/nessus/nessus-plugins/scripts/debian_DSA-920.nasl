# This script was automatically generated from the dsa-920
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been discovered in ethereal, a commonly used
network traffic analyser that causes a denial of service and may
potentially allow the execution of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 0.9.4-1woody14.
For the stable distribution (sarge) this problem has been fixed in
version 0.10.10-2sarge3.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your ethereal packages.


Solution : http://www.debian.org/security/2005/dsa-920
Risk factor : High';

if (description) {
 script_id(22786);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "920");
 script_cve_id("CVE-2005-3651");
 script_bugtraq_id(15794);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA920] DSA-920-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-920-1 ethereal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.0.\nUpgrade to ethereal_0.9.4-1woody14\n');
}
if (deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-common is vulnerable in Debian 3.0.\nUpgrade to ethereal-common_0.9.4-1woody14\n');
}
if (deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-dev is vulnerable in Debian 3.0.\nUpgrade to ethereal-dev_0.9.4-1woody14\n');
}
if (deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tethereal is vulnerable in Debian 3.0.\nUpgrade to tethereal_0.9.4-1woody14\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.1.\nUpgrade to ethereal_0.10.10-2sarge4\n');
}
if (deb_check(prefix: 'ethereal-common', release: '3.1', reference: '0.10.10-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-common is vulnerable in Debian 3.1.\nUpgrade to ethereal-common_0.10.10-2sarge4\n');
}
if (deb_check(prefix: 'ethereal-dev', release: '3.1', reference: '0.10.10-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-dev is vulnerable in Debian 3.1.\nUpgrade to ethereal-dev_0.10.10-2sarge4\n');
}
if (deb_check(prefix: 'tethereal', release: '3.1', reference: '0.10.10-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tethereal is vulnerable in Debian 3.1.\nUpgrade to tethereal_0.10.10-2sarge4\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.10-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian sarge.\nUpgrade to ethereal_0.10.10-2sarge3\n');
}
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian woody.\nUpgrade to ethereal_0.9.4-1woody14\n');
}
if (w) { security_hole(port: 0, data: desc); }
