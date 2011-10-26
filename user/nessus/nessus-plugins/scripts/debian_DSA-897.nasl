# This script was automatically generated from the dsa-897
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in phpsysinfo, a PHP
based host information application.  The Common Vulnerabilities and
Exposures project identifies the following problems: 
    Maksymilian Arciemowicz discovered several cross site scripting
    problems, of which not all were fixed in DSA 724.
    Christopher Kunz discovered that local variables get overwritten
    unconditionally and are trusted later, which could lead to the
    inclusion of arbitrary files.
    Christopher Kunz discovered that user-supplied input is used
    unsanitised, causing a HTTP Response splitting problem.
For the old stable distribution (woody) these problems have been fixed in
version 2.0-3woody3.
For the stable distribution (sarge) these problems have been fixed in
version 2.3-4sarge1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your phpsysinfo package.


Solution : http://www.debian.org/security/2005/dsa-897
Risk factor : High';

if (description) {
 script_id(22763);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "897");
 script_cve_id("CVE-2005-0870", "CVE-2005-3347", "CVE-2005-3348");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA897] DSA-897-1 phpsysinfo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-897-1 phpsysinfo");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'phpsysinfo', release: '3.0', reference: '2.0-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpsysinfo is vulnerable in Debian 3.0.\nUpgrade to phpsysinfo_2.0-3woody3\n');
}
if (deb_check(prefix: 'phpsysinfo', release: '3.1', reference: '2.3-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpsysinfo is vulnerable in Debian 3.1.\nUpgrade to phpsysinfo_2.3-4sarge1\n');
}
if (deb_check(prefix: 'phpsysinfo', release: '3.1', reference: '2.3-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpsysinfo is vulnerable in Debian sarge.\nUpgrade to phpsysinfo_2.3-4sarge1\n');
}
if (deb_check(prefix: 'phpsysinfo', release: '3.0', reference: '2.0-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpsysinfo is vulnerable in Debian woody.\nUpgrade to phpsysinfo_2.0-3woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
