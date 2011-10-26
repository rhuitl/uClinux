# This script was automatically generated from the dsa-785
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It has been discovered that libpam-ldap, the Pluggable Authentication
Module allowing LDAP interfaces, ignores the result of an attempt to
authenticate against an LDAP server that does not set an optional data
field.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 178-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 178-1sarge1.
We recommend that you upgrade your libpam-ldap package.


Solution : http://www.debian.org/security/2005/dsa-785
Risk factor : High';

if (description) {
 script_id(19528);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "785");
 script_cve_id("CVE-2005-2069", "CVE-2005-2641");
 script_xref(name: "CERT", value: "778916");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA785] DSA-785-1 libpam-ldap");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-785-1 libpam-ldap");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpam-ldap', release: '', reference: '178-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-ldap is vulnerable in Debian .\nUpgrade to libpam-ldap_178-1sarge1\n');
}
if (deb_check(prefix: 'libpam-ldap', release: '3.1', reference: '178-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-ldap is vulnerable in Debian 3.1.\nUpgrade to libpam-ldap_178-1sarge1\n');
}
if (deb_check(prefix: 'libpam-ldap', release: '3.1', reference: '178-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpam-ldap is vulnerable in Debian sarge.\nUpgrade to libpam-ldap_178-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
