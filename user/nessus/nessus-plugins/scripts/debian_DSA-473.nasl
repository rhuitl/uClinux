# This script was automatically generated from the dsa-473
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in oftpd, an anonymous FTP server,
whereby a remote attacker could cause the oftpd process to crash by
specifying a large value in a PORT command.
For the stable distribution (woody) this problem has been fixed in
version 0.3.6-6.
For the unstable distribution (sid) these problems have been fixed in
version 20040304-1.
We recommend that you update your oftpd package.


Solution : http://www.debian.org/security/2004/dsa-473
Risk factor : High';

if (description) {
 script_id(15310);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "473");
 script_cve_id("CVE-2004-0376");
 script_bugtraq_id(9980);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA473] DSA-473-1 oftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-473-1 oftpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'oftpd', release: '3.0', reference: '0.3.6-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package oftpd is vulnerable in Debian 3.0.\nUpgrade to oftpd_0.3.6-6\n');
}
if (deb_check(prefix: 'oftpd', release: '3.1', reference: '20040304-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package oftpd is vulnerable in Debian 3.1.\nUpgrade to oftpd_20040304-1\n');
}
if (deb_check(prefix: 'oftpd', release: '3.0', reference: '0.3.6-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package oftpd is vulnerable in Debian woody.\nUpgrade to oftpd_0.3.6-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
