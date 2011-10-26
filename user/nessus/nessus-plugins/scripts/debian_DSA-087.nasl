# This script was automatically generated from the dsa-087
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
CORE ST reports that an exploit has been found for a bug in the wu-ftpd
glob code (this is the code that handles filename wildcard expansion).
Any logged in user (including anonymous FTP users) can exploit the bug
to gain root privileges on the server. 

This has been corrected in version 2.6.0-6 of the wu-ftpd package.



Solution : http://www.debian.org/security/2001/dsa-087
Risk factor : High';

if (description) {
 script_id(14924);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "087");
 script_cve_id("CVE-2001-0550");
 script_bugtraq_id(3581);
 script_xref(name: "CERT", value: "886083");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA087] DSA-087-1 wu-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-087-1 wu-ftpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wu-ftpd', release: '2.2', reference: '2.6.0-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian 2.2.\nUpgrade to wu-ftpd_2.6.0-6\n');
}
if (deb_check(prefix: 'wu-ftpd-academ', release: '2.2', reference: '2.6.0-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd-academ is vulnerable in Debian 2.2.\nUpgrade to wu-ftpd-academ_2.6.0-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
