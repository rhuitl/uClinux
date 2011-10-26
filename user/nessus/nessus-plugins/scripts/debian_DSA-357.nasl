# This script was automatically generated from the dsa-357
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
iSEC Security Research reports that wu-ftpd contains an off-by-one bug
in the fb_realpath function which could be exploited by a logged-in user
(local or anonymous) to gain root privileges. A demonstration exploit is
reportedly available.
For the current stable distribution (woody) this problem has been fixed
in version 2.6.2-3woody1. 
For the unstable distribution (sid) an update will be available shortly.
We recommend you upgrade your wu-ftpd package immediately.


Solution : http://www.debian.org/security/2003/dsa-357
Risk factor : High';

if (description) {
 script_id(15194);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "357");
 script_cve_id("CVE-2003-0466");
 script_bugtraq_id(8315);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA357] DSA-357-1 wu-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-357-1 wu-ftpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wu-ftpd', release: '3.0', reference: '2.6.2-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian 3.0.\nUpgrade to wu-ftpd_2.6.2-3woody1\n');
}
if (deb_check(prefix: 'wu-ftpd-academ', release: '3.0', reference: '2.6.2-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd-academ is vulnerable in Debian 3.0.\nUpgrade to wu-ftpd-academ_2.6.2-3woody1\n');
}
if (deb_check(prefix: 'wu-ftpd', release: '3.0', reference: '2.6.2-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian woody.\nUpgrade to wu-ftpd_2.6.2-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
