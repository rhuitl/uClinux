# This script was automatically generated from the dsa-511
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several buffer overflow vulnerabilities were discovered in ethereal, a
network traffic analyzer.  These vulnerabilities are described in the
ethereal advisory "enpa-sa-00013".  Of these, only some parts of
CVE-2004-0176 affect the version of ethereal in Debian woody.
CVE-2004-0367 and CVE-2004-0365 are not applicable to this version.
For the current stable distribution (woody), these problems have been
fixed in version 0.9.4-1woody7.
For the unstable distribution (sid), these problems have been fixed in
version 0.10.3-1.
We recommend that you update your ethereal package.


Solution : http://www.debian.org/security/2004/dsa-511
Risk factor : High';

if (description) {
 script_id(15348);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "511");
 script_cve_id("CVE-2004-0176");
 script_bugtraq_id(9952);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA511] DSA-511-1 ethereal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-511-1 ethereal");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.0.\nUpgrade to ethereal_0.9.4-1woody7\n');
}
if (deb_check(prefix: 'ethereal-common', release: '3.0', reference: '0.9.4-1woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-common is vulnerable in Debian 3.0.\nUpgrade to ethereal-common_0.9.4-1woody7\n');
}
if (deb_check(prefix: 'ethereal-dev', release: '3.0', reference: '0.9.4-1woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal-dev is vulnerable in Debian 3.0.\nUpgrade to ethereal-dev_0.9.4-1woody7\n');
}
if (deb_check(prefix: 'tethereal', release: '3.0', reference: '0.9.4-1woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tethereal is vulnerable in Debian 3.0.\nUpgrade to tethereal_0.9.4-1woody7\n');
}
if (deb_check(prefix: 'ethereal', release: '3.1', reference: '0.10.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian 3.1.\nUpgrade to ethereal_0.10.3-1\n');
}
if (deb_check(prefix: 'ethereal', release: '3.0', reference: '0.9.4-1woody7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ethereal is vulnerable in Debian woody.\nUpgrade to ethereal_0.9.4-1woody7\n');
}
if (w) { security_hole(port: 0, data: desc); }
