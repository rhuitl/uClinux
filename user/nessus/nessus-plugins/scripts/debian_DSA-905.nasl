# This script was automatically generated from the dsa-905
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in Mantis, a
web-based bug tracking system.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    A cross-site scripting vulnerability allows attackers to inject
    arbitrary web script or HTML.
    A file inclusion vulnerability allows remote attackers to execute
    arbitrary PHP code and include arbitrary local files.
    An SQL injection vulnerability allows remote attackers to execute
    arbitrary SQL commands.
    Mantis can be tricked into displaying the otherwise hidden real
    mail address of its users.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 0.19.2-4.1.
For the unstable distribution (sid) these problems have been fixed in
version 0.19.3-0.1.
We recommend that you upgrade your mantis package.


Solution : http://www.debian.org/security/2005/dsa-905
Risk factor : High';

if (description) {
 script_id(22771);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "905");
 script_cve_id("CVE-2005-3091", "CVE-2005-3335", "CVE-2005-3336", "CVE-2005-3338", "CVE-2005-3339");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA905] DSA-905-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-905-1 mantis");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mantis', release: '', reference: '0.19.3-0.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian .\nUpgrade to mantis_0.19.3-0.1\n');
}
if (deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian 3.1.\nUpgrade to mantis_0.19.2-4.1\n');
}
if (deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian sarge.\nUpgrade to mantis_0.19.2-4.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
