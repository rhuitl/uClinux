# This script was automatically generated from the dsa-551
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Przemyslaw Frasunek discovered a vulnerability in tnftpd or lukemftpd
respectively, the enhanced ftp daemon from NetBSD.  An attacker could
utilise this to execute arbitrary code on the server.
For the stable distribution (woody) this problem has been fixed in
version 1.1-1woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1.1-2.2.
We recommend that you upgrade your lukemftpd package.


Solution : http://www.debian.org/security/2004/dsa-551
Risk factor : High';

if (description) {
 script_id(15388);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "551");
 script_cve_id("CVE-2004-0794");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA551] DSA-551-1 lukemftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-551-1 lukemftpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lukemftpd', release: '3.0', reference: '1.1-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lukemftpd is vulnerable in Debian 3.0.\nUpgrade to lukemftpd_1.1-1woody2\n');
}
if (deb_check(prefix: 'lukemftpd', release: '3.1', reference: '1.1-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lukemftpd is vulnerable in Debian 3.1.\nUpgrade to lukemftpd_1.1-2.2\n');
}
if (deb_check(prefix: 'lukemftpd', release: '3.0', reference: '1.1-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lukemftpd is vulnerable in Debian woody.\nUpgrade to lukemftpd_1.1-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
