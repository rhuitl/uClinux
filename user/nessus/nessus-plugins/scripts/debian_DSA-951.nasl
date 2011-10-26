# This script was automatically generated from the dsa-951
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
This update corrects the search feature in trac, an enhanced wiki
and issue tracking system for software development projects, which
broke with the last security update.  For completeness please find
below the original advisory text:
Several vulnerabilities have been discovered in trac, an enhanced wiki
and issue tracking system for software development projects.  The
Common Vulnerabilities and Exposures project identifies the following
problems:
    Due to missing input sanitising it is possible to inject arbitrary
    SQL code into the SQL statements.
    A cross-site scripting vulnerability has been discovered that
    allows remote attackers to inject arbitrary web script or HTML.
The old stable distribution (woody) does not contain trac packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.8.1-3sarge4.
For the unstable distribution (sid) these problems have been fixed in
version 0.9.3-1.
We recommend that you upgrade your trac package.


Solution : http://www.debian.org/security/2006/dsa-951
Risk factor : High';

if (description) {
 script_id(22817);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "951");
 script_cve_id("CVE-2005-4065", "CVE-2005-4644");
 script_bugtraq_id(15720, 16198);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA951] DSA-951-2 trac");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-951-2 trac");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'trac', release: '', reference: '0.9.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package trac is vulnerable in Debian .\nUpgrade to trac_0.9.3-1\n');
}
if (deb_check(prefix: 'trac', release: '3.1', reference: '0.8.1-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package trac is vulnerable in Debian 3.1.\nUpgrade to trac_0.8.1-3sarge4\n');
}
if (deb_check(prefix: 'trac', release: '3.1', reference: '0.8.1-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package trac is vulnerable in Debian sarge.\nUpgrade to trac_0.8.1-3sarge4\n');
}
if (w) { security_hole(port: 0, data: desc); }
