# This script was automatically generated from the dsa-967
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security problems have been found in elog, an electronic logbook
to manage notes.  The Common Vulnerabilities and Exposures Project
identifies the following problems:
    "GroundZero Security" discovered that elog insufficiently checks the
    size of a buffer used for processing URL parameters, which might lead
    to the execution of arbitrary code.
    It was discovered that elog contains a directory traveral vulnerability
    in the processing of "../" sequences in URLs, which might lead to
    information disclosure.
    The code to write the log file contained a format string vulnerability,
    which might lead to the execution of arbitrary code.
    Overly long revision attributes might trigger a crash due to a buffer
    overflow.
    The code to write the log file does not enforce bounds checks properly,
    which might lead to the execution of arbitrary code.
    elog emitted different errors messages for invalid passwords and invalid
    users, which allows an attacker to probe for valid user names.
    An attacker could be driven into infinite redirection with a crafted
    "fail" request, which has denial of service potential.
The old stable distribution (woody) does not contain elog packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.5.7+r1558-4+sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 2.6.1+r1642-1.
We recommend that you upgrade your elog package.


Solution : http://www.debian.org/security/2006/dsa-967
Risk factor : High';

if (description) {
 script_id(22833);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "967");
 script_cve_id("CVE-2005-4439", "CVE-2006-0347", "CVE-2006-0348", "CVE-2006-0597", "CVE-2006-0598", "CVE-2006-0599", "CVE-2006-0600");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA967] DSA-967-1 elog");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-967-1 elog");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'elog', release: '', reference: '2.6.1+r1642-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package elog is vulnerable in Debian .\nUpgrade to elog_2.6.1+r1642-1\n');
}
if (deb_check(prefix: 'elog', release: '3.1', reference: '2.5.7+r1558-4+sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package elog is vulnerable in Debian 3.1.\nUpgrade to elog_2.5.7+r1558-4+sarge2\n');
}
if (deb_check(prefix: 'elog', release: '3.1', reference: '2.5.7+r1558-4+sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package elog is vulnerable in Debian sarge.\nUpgrade to elog_2.5.7+r1558-4+sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
