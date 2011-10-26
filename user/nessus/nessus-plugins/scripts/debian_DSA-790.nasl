# This script was automatically generated from the dsa-790
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Alexander Gerasiov discovered that phpldapadmin, a web based interface
for administering LDAP servers, allows anybody to access the LDAP
server anonymously, even if this is disabled in the configuration with
the "disable_anon_bind" statement.
The old stable distribution (woody) is not vulnerable to this problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.5-3sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.6c-5.
We recommend that you upgrade your phpldapadmin package.


Solution : http://www.debian.org/security/2005/dsa-790
Risk factor : High';

if (description) {
 script_id(19560);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "790");
 script_cve_id("CVE-2005-2654");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA790] DSA-790-1 phpldapadmin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-790-1 phpldapadmin");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'phpldapadmin', release: '', reference: '0.9.6c-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpldapadmin is vulnerable in Debian .\nUpgrade to phpldapadmin_0.9.6c-5\n');
}
if (deb_check(prefix: 'phpldapadmin', release: '3.1', reference: '0.9.5-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpldapadmin is vulnerable in Debian 3.1.\nUpgrade to phpldapadmin_0.9.5-3sarge2\n');
}
if (deb_check(prefix: 'phpldapadmin', release: '3.1', reference: '0.9.5-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpldapadmin is vulnerable in Debian sarge.\nUpgrade to phpldapadmin_0.9.5-3sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
