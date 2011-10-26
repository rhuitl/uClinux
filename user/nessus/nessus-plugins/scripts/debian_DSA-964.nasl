# This script was automatically generated from the dsa-964
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in gnocatan, the computer version of the
settlers of Catan boardgame, that can lead the server and other clients
to exit via an assert, and hence does not permit the execution of
arbitrary code.  The game has been renamed into Pioneers after the
release of Debian sarge.
For the old stable distribution (woody) this problem has been fixed in
version 0.6.1-5woody3.
For the stable distribution (sarge) this problem has been fixed in
version 0.8.1.59-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.49-1 of pioneers.
We recommend that you upgrade your gnocatan and pioneers packages.


Solution : http://www.debian.org/security/2006/dsa-964
Risk factor : High';

if (description) {
 script_id(22830);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "964");
 script_cve_id("CVE-2006-0467");
 script_bugtraq_id(16429);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA964] DSA-964-1 gnocatan");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-964-1 gnocatan");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnocatan', release: '', reference: '0.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan is vulnerable in Debian .\nUpgrade to gnocatan_0.9\n');
}
if (deb_check(prefix: 'gnocatan-client', release: '3.0', reference: '0.6.1-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-client is vulnerable in Debian 3.0.\nUpgrade to gnocatan-client_0.6.1-5woody3\n');
}
if (deb_check(prefix: 'gnocatan-data', release: '3.0', reference: '0.6.1-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-data is vulnerable in Debian 3.0.\nUpgrade to gnocatan-data_0.6.1-5woody3\n');
}
if (deb_check(prefix: 'gnocatan-help', release: '3.0', reference: '0.6.1-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-help is vulnerable in Debian 3.0.\nUpgrade to gnocatan-help_0.6.1-5woody3\n');
}
if (deb_check(prefix: 'gnocatan-server', release: '3.0', reference: '0.6.1-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-server is vulnerable in Debian 3.0.\nUpgrade to gnocatan-server_0.6.1-5woody3\n');
}
if (deb_check(prefix: 'gnocatan-ai', release: '3.1', reference: '0.8.1.59-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-ai is vulnerable in Debian 3.1.\nUpgrade to gnocatan-ai_0.8.1.59-1sarge1\n');
}
if (deb_check(prefix: 'gnocatan-client', release: '3.1', reference: '0.8.1.59-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-client is vulnerable in Debian 3.1.\nUpgrade to gnocatan-client_0.8.1.59-1sarge1\n');
}
if (deb_check(prefix: 'gnocatan-help', release: '3.1', reference: '0.8.1.59-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-help is vulnerable in Debian 3.1.\nUpgrade to gnocatan-help_0.8.1.59-1sarge1\n');
}
if (deb_check(prefix: 'gnocatan-meta-server', release: '3.1', reference: '0.8.1.59-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-meta-server is vulnerable in Debian 3.1.\nUpgrade to gnocatan-meta-server_0.8.1.59-1sarge1\n');
}
if (deb_check(prefix: 'gnocatan-server-console', release: '3.1', reference: '0.8.1.59-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-server-console is vulnerable in Debian 3.1.\nUpgrade to gnocatan-server-console_0.8.1.59-1sarge1\n');
}
if (deb_check(prefix: 'gnocatan-server-data', release: '3.1', reference: '0.8.1.59-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-server-data is vulnerable in Debian 3.1.\nUpgrade to gnocatan-server-data_0.8.1.59-1sarge1\n');
}
if (deb_check(prefix: 'gnocatan-server-gtk', release: '3.1', reference: '0.8.1.59-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan-server-gtk is vulnerable in Debian 3.1.\nUpgrade to gnocatan-server-gtk_0.8.1.59-1sarge1\n');
}
if (deb_check(prefix: 'gnocatan', release: '3.1', reference: '0.8.1.59-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan is vulnerable in Debian sarge.\nUpgrade to gnocatan_0.8.1.59-1sarge1\n');
}
if (deb_check(prefix: 'gnocatan', release: '3.0', reference: '0.6.1-5woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnocatan is vulnerable in Debian woody.\nUpgrade to gnocatan_0.6.1-5woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
