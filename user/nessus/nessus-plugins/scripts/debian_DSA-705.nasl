# This script was automatically generated from the dsa-705
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several denial of service conditions have been discovered in wu-ftpd,
the popular FTP daemon.  The Common Vulnerabilities and Exposures
project identifies the following problems:
    Adam Zabrocki discovered a denial of service condition in wu-ftpd
    that could be exploited by a remote user and cause the server to
    slow down by resource exhaustion.
    Georgi Guninski discovered that /bin/ls may be called from within
    wu-ftpd in a way that will result in large memory consumption and
    hence slow down the server.
For the stable distribution (woody) these problems have been fixed in
version 2.6.2-3woody5.
For the unstable distribution (sid) these problems have been fixed in
version 2.6.2-19.
We recommend that you upgrade your wu-ftpd package.


Solution : http://www.debian.org/security/2005/dsa-705
Risk factor : High';

if (description) {
 script_id(18010);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "705");
 script_cve_id("CVE-2003-0854", "CVE-2005-0256");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA705] DSA-705-1 wu-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-705-1 wu-ftpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wu-ftpd', release: '3.0', reference: '2.6.2-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian 3.0.\nUpgrade to wu-ftpd_2.6.2-3woody5\n');
}
if (deb_check(prefix: 'wu-ftpd-academ', release: '3.0', reference: '2.6.2-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd-academ is vulnerable in Debian 3.0.\nUpgrade to wu-ftpd-academ_2.6.2-3woody5\n');
}
if (deb_check(prefix: 'wu-ftpd', release: '3.1', reference: '2.6.2-19')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian 3.1.\nUpgrade to wu-ftpd_2.6.2-19\n');
}
if (deb_check(prefix: 'wu-ftpd', release: '3.0', reference: '2.6.2-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian woody.\nUpgrade to wu-ftpd_2.6.2-3woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
