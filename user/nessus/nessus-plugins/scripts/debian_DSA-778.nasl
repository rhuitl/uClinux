# This script was automatically generated from the dsa-778
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two security related problems have been discovered in Mantis, a
web-based bug tracking system.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    A remote attacker could supply a specially crafted URL to scan
    arbitrary ports on arbitrary hosts that may not be accessible
    otherwise.
    A remote attacker was able to insert arbitrary HTML code in bug
    reports, hence, cross site scripting.
    A remote attacker was able to insert arbitrary HTML code in bug
    reports, hence, cross site scripting.
The old stable distribution (woody) does not seem to be affected by
these problems.
For the stable distribution (sarge) these problems have been fixed in
version 0.19.2-4.
For the unstable distribution (sid) these problems have been fixed in
version 0.19.2-4.
We recommend that you upgrade your mantis package.


Solution : http://www.debian.org/security/2005/dsa-778
Risk factor : High';

if (description) {
 script_id(19475);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "778");
 script_cve_id("CVE-2005-2556", "CVE-2005-2557", "CVE-2005-3090");
 script_bugtraq_id(14604);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA778] DSA-778-1 mantis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-778-1 mantis");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mantis', release: '', reference: '0.19.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian .\nUpgrade to mantis_0.19.2-4\n');
}
if (deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian 3.1.\nUpgrade to mantis_0.19.2-4\n');
}
if (deb_check(prefix: 'mantis', release: '3.1', reference: '0.19.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mantis is vulnerable in Debian sarge.\nUpgrade to mantis_0.19.2-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
