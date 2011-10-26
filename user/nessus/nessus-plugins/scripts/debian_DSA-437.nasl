# This script was automatically generated from the dsa-437
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in cgiemail, a CGI program used to
email the contents of an HTML form, whereby it could be used to send
email to arbitrary addresses.  This type of vulnerability is commonly
exploited to send unsolicited commercial email (spam).
For the current stable distribution (woody) this problem has been
fixed in version 1.6-14woody1.
For the unstable distribution (sid), this problem has been fixed in
version 1.6-20.
We recommend that you update your cgiemail package.


Solution : http://www.debian.org/security/2004/dsa-437
Risk factor : High';

if (description) {
 script_id(15274);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "437");
 script_cve_id("CVE-2002-1575");
 script_bugtraq_id(5013);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA437] DSA-437-1 cgiemail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-437-1 cgiemail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cgiemail', release: '3.0', reference: '1.6-14woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cgiemail is vulnerable in Debian 3.0.\nUpgrade to cgiemail_1.6-14woody1\n');
}
if (deb_check(prefix: 'cgiemail', release: '3.1', reference: '1.6-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cgiemail is vulnerable in Debian 3.1.\nUpgrade to cgiemail_1.6-20\n');
}
if (deb_check(prefix: 'cgiemail', release: '3.0', reference: '1.6-14woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cgiemail is vulnerable in Debian woody.\nUpgrade to cgiemail_1.6-14woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
