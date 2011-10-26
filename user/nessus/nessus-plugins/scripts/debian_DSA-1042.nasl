# This script was automatically generated from the dsa-1042
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The Mu Security research team discovered a denial of service condition
in the Simple Authentication and Security Layer authentication library
(SASL) during DIGEST-MD5 negotiation.  This potentially affects
multiple products that use SASL DIGEST-MD5 authentication including
OpenLDAP, Sendmail, Postfix, etc.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.1.19-1.5sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.1.19.dfsg1-0.2.
We recommend that you upgrade your cyrus-sasl2 packages.


Solution : http://www.debian.org/security/2006/dsa-1042
Risk factor : High';

if (description) {
 script_id(22584);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1042");
 script_cve_id("CVE-2006-1721");
 script_bugtraq_id(17446);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1042] DSA-1042-1 cyrus-sasl2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1042-1 cyrus-sasl2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cyrus-sasl2', release: '', reference: '2.1.19.dfsg1-0.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-sasl2 is vulnerable in Debian .\nUpgrade to cyrus-sasl2_2.1.19.dfsg1-0.2\n');
}
if (deb_check(prefix: 'libsasl2', release: '3.1', reference: '2.1.19-1.5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl2 is vulnerable in Debian 3.1.\nUpgrade to libsasl2_2.1.19-1.5sarge1\n');
}
if (deb_check(prefix: 'libsasl2-dev', release: '3.1', reference: '2.1.19-1.5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl2-dev is vulnerable in Debian 3.1.\nUpgrade to libsasl2-dev_2.1.19-1.5sarge1\n');
}
if (deb_check(prefix: 'libsasl2-modules', release: '3.1', reference: '2.1.19-1.5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl2-modules is vulnerable in Debian 3.1.\nUpgrade to libsasl2-modules_2.1.19-1.5sarge1\n');
}
if (deb_check(prefix: 'libsasl2-modules-gssapi-heimdal', release: '3.1', reference: '2.1.19-1.5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl2-modules-gssapi-heimdal is vulnerable in Debian 3.1.\nUpgrade to libsasl2-modules-gssapi-heimdal_2.1.19-1.5sarge1\n');
}
if (deb_check(prefix: 'libsasl2-modules-kerberos-heimdal', release: '3.1', reference: '2.1.19-1.5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl2-modules-kerberos-heimdal is vulnerable in Debian 3.1.\nUpgrade to libsasl2-modules-kerberos-heimdal_2.1.19-1.5sarge1\n');
}
if (deb_check(prefix: 'libsasl2-modules-sql', release: '3.1', reference: '2.1.19-1.5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsasl2-modules-sql is vulnerable in Debian 3.1.\nUpgrade to libsasl2-modules-sql_2.1.19-1.5sarge1\n');
}
if (deb_check(prefix: 'sasl2-bin', release: '3.1', reference: '2.1.19-1.5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sasl2-bin is vulnerable in Debian 3.1.\nUpgrade to sasl2-bin_2.1.19-1.5sarge1\n');
}
if (deb_check(prefix: 'cyrus-sasl2', release: '3.1', reference: '2.1.19-1.5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-sasl2 is vulnerable in Debian sarge.\nUpgrade to cyrus-sasl2_2.1.19-1.5sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
