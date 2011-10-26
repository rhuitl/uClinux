# This script was automatically generated from the dsa-364
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
man-db provides the standard man(1) command on Debian systems.  During
configuration of this package, the administrator is asked whether
man(1) should run setuid to a dedicated user ("man") in order to
provide a shared cache of preformatted manual pages.  The default is
for man(1) NOT to be setuid, and in this configuration no known
vulnerability exists.  However, if the user explicitly requests setuid
operation, a local attacker could exploit either of the following bugs to
execute arbitrary code as the "man" user.
Again, these vulnerabilities do not affect the default configuration,
where man is not setuid.
For the current stable distribution (woody), these problems have been
fixed in version 2.3.20-18.woody.4.
For the unstable distribution (sid), these problems have been fixed in
version 2.4.1-13.
We recommend that you update your man-db package.


Solution : http://www.debian.org/security/2003/dsa-364
Risk factor : High';

if (description) {
 script_id(15201);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "364");
 script_cve_id("CVE-2003-0620", "CVE-2003-0645");
 script_bugtraq_id(8303, 8341);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA364] DSA-364-3 man-db");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-364-3 man-db");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'man-db', release: '3.0', reference: '2.3.20-18.woody.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package man-db is vulnerable in Debian 3.0.\nUpgrade to man-db_2.3.20-18.woody.4\n');
}
if (deb_check(prefix: 'man-db', release: '3.1', reference: '2.4.1-13')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package man-db is vulnerable in Debian 3.1.\nUpgrade to man-db_2.4.1-13\n');
}
if (deb_check(prefix: 'man-db', release: '3.0', reference: '2.3.20-18.woody.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package man-db is vulnerable in Debian woody.\nUpgrade to man-db_2.3.20-18.woody.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
