# This script was automatically generated from the dsa-315
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Bas Wijnen discovered that the gnocatan server is vulnerable to
several buffer overflows which could be exploited to execute arbitrary
code on the server system.
For the stable distribution (woody), this problem has been fixed in
version 0.6.1-5woody2.
The old stable distribution (potato) does not contain a gnocatan package.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your gnocatan package.


Solution : http://www.debian.org/security/2003/dsa-315
Risk factor : High';

if (description) {
 script_id(15152);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "315");
 script_cve_id("CVE-2003-0433");
 script_bugtraq_id(7877);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA315] DSA-315-1 gnocatan");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-315-1 gnocatan");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnocatan-client', release: '3.0', reference: '0.6.1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-client is vulnerable in Debian 3.0.\nUpgrade to gnocatan-client_0.6.1-5woody2\n');
}
if (deb_check(prefix: 'gnocatan-data', release: '3.0', reference: '0.6.1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-data is vulnerable in Debian 3.0.\nUpgrade to gnocatan-data_0.6.1-5woody2\n');
}
if (deb_check(prefix: 'gnocatan-help', release: '3.0', reference: '0.6.1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-help is vulnerable in Debian 3.0.\nUpgrade to gnocatan-help_0.6.1-5woody2\n');
}
if (deb_check(prefix: 'gnocatan-server', release: '3.0', reference: '0.6.1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-server is vulnerable in Debian 3.0.\nUpgrade to gnocatan-server_0.6.1-5woody2\n');
}
if (deb_check(prefix: 'gnocatan', release: '3.0', reference: '0.6.1-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan is vulnerable in Debian woody.\nUpgrade to gnocatan_0.6.1-5woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
