# This script was automatically generated from the dsa-1057
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several cross-site scripting vulnerabilities have been discovered in
phpLDAPadmin, a web based interface for administering LDAP servers,
that allows remote attackers to inject arbitrary web script or HTML.
The old stable distribution (woody) does not contain phpldapadmin
packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.9.5-3sarge3.
For the unstable distribution (sid) these problems have been fixed in
version 0.9.8.3-1.
We recommend that you upgrade your phpldapadmin package.


Solution : http://www.debian.org/security/2006/dsa-1057
Risk factor : High';

if (description) {
 script_id(22599);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1057");
 script_cve_id("CVE-2006-2016");
 script_bugtraq_id(17643);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1057] DSA-1057-1 phpldapadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1057-1 phpldapadmin");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'phpldapadmin', release: '', reference: '0.9.8.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpldapadmin is vulnerable in Debian .\nUpgrade to phpldapadmin_0.9.8.3-1\n');
}
if (deb_check(prefix: 'phpldapadmin', release: '3.1', reference: '0.9.5-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpldapadmin is vulnerable in Debian 3.1.\nUpgrade to phpldapadmin_0.9.5-3sarge3\n');
}
if (deb_check(prefix: 'phpldapadmin', release: '3.1', reference: '0.9.5-3sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpldapadmin is vulnerable in Debian sarge.\nUpgrade to phpldapadmin_0.9.5-3sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
