# This script was automatically generated from the dsa-944
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in Mantis, a
web-based bug tracking system. The Common Vulnerabilities and
Exposures project identifies the following problems:
    Missing input sanitising allows remote attackers  to inject
    arbitrary web script or HTML.
    Tobias Klein discovered that Mantis allows remote attackers to
    bypass the file upload size restriction.
    Tobias Klein discovered several SQL injection vulnerabilities that
    allow remote attackers to execute arbitrary SQL commands.
    Tobias Klein discovered unspecified "port injection"
    vulnerabilities in filters.
    Tobias Klein discovered a CRLF injection vulnerability that allows
    remote attackers to modify HTTP headers and conduct HTTP response
    splitting attacks.
    Tobias Klein discovered several cross-site scripting (XSS)
    vulnerabilities that allow remote attackers to inject arbitrary
    web script or HTML.
    Tobias Klein discovered that Mantis discloses private bugs via
    public RSS feeds, which allows remote attackers to obtain
    sensitive information.
    Tobias Klein discovered that Mantis does not properly handle "Make
    note private" when a bug is being resolved, which has unknown
    impact and attack vectors, probably related to an information
    leak.
The old stable distribution (woody) does not seem to be affected by
these problems.
For the stable distribution (sarge) these problems have been fixed in
version 0.19.2-5sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 0.19.4-1.
We recommend that you upgrade your mantis package.


Solution : http://www.debian.org/security/2006/dsa-944
Risk factor : High';

if (description) {
 script_id(22810);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "944");
 script_cve_id("CVE-2005-4238", "CVE-2005-4518", "CVE-2005-4519", "CVE-2005-4520", "CVE-2005-4521", "CVE-2005-4522", "CVE-2005-4523");
 script_bugtraq_id(15842, 16046);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA944] DSA-944-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-944-1 mantis");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mantis', release: '', reference: '0.19.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian .\nUpgrade to mantis_0.19.4-1\n');
}
if (deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian 3.1.\nUpgrade to mantis_0.19.2-5sarge1\n');
}
if (deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian sarge.\nUpgrade to mantis_0.19.2-5sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
