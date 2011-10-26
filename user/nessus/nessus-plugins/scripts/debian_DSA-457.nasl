# This script was automatically generated from the dsa-457
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities were discovered in wu-ftpd:
 Glenn Stewart discovered that users could bypass the
 directory access restrictions imposed by the restricted-gid option by
 changing the permissions on their home directory.  On a subsequent
 login, when access to the user\'s home directory was denied, wu-ftpd
 would fall back to the root directory.
 A buffer overflow existed in wu-ftpd\'s code which
 deals with S/key authentication.
For the stable distribution (woody) these problems have been fixed in
version 2.6.2-3woody4.
For the unstable distribution (sid) these problems have been fixed in
version 2.6.2-17.1.
We recommend that you update your wu-ftpd package.


Solution : http://www.debian.org/security/2004/dsa-457
Risk factor : High';

if (description) {
 script_id(15294);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "457");
 script_cve_id("CVE-2004-0148", "CVE-2004-0185");
 script_bugtraq_id(9832);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA457] DSA-457-1 wu-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-457-1 wu-ftpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wu-ftpd', release: '3.0', reference: '2.6.2-3woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian 3.0.\nUpgrade to wu-ftpd_2.6.2-3woody4\n');
}
if (deb_check(prefix: 'wu-ftpd-academ', release: '3.0', reference: '2.6.2-3woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd-academ is vulnerable in Debian 3.0.\nUpgrade to wu-ftpd-academ_2.6.2-3woody4\n');
}
if (deb_check(prefix: 'wu-ftpd', release: '3.1', reference: '2.6.2-17.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian 3.1.\nUpgrade to wu-ftpd_2.6.2-17.1\n');
}
if (deb_check(prefix: 'wu-ftpd', release: '3.0', reference: '2.6.2-3woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian woody.\nUpgrade to wu-ftpd_2.6.2-3woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
