# This script was automatically generated from the dsa-952
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"Seregorn" discovered a format string vulnerability in the logging
function of libapache-auth-ldap, an LDAP authentication module for the
Apache webserver, that can lead to the execution of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 1.6.0-3.1.
For the stable distribution (sarge) this problem has been fixed in
version 1.6.0-8.1
The unstable distribution (sid) does no longer contain libapache-auth-ldap.
We recommend that you upgrade your libapache-auth-ldap package.


Solution : http://www.debian.org/security/2006/dsa-952
Risk factor : High';

if (description) {
 script_id(22818);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "952");
 script_cve_id("CVE-2006-0150");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA952] DSA-952-1 libapache-auth-ldap");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-952-1 libapache-auth-ldap");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libapache-auth-ldap', release: '3.0', reference: '1.6.0-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-auth-ldap is vulnerable in Debian 3.0.\nUpgrade to libapache-auth-ldap_1.6.0-3.1\n');
}
if (deb_check(prefix: 'libapache-auth-ldap', release: '3.1', reference: '1.6.0-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-auth-ldap is vulnerable in Debian 3.1.\nUpgrade to libapache-auth-ldap_1.6.0-8.1\n');
}
if (deb_check(prefix: 'libapache-auth-ldap', release: '3.1', reference: '1.6.0-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-auth-ldap is vulnerable in Debian sarge.\nUpgrade to libapache-auth-ldap_1.6.0-8\n');
}
if (deb_check(prefix: 'libapache-auth-ldap', release: '3.0', reference: '1.6.0-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-auth-ldap is vulnerable in Debian woody.\nUpgrade to libapache-auth-ldap_1.6.0-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
