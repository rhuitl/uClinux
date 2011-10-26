# This script was automatically generated from the dsa-541
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Markus Wörle discovered a cross site scripting problem in
status-display (list.cgi) of the icecast internal webserver, an MPEG
layer III streaming server.  The UserAgent variable is not properly
html_escaped so that an attacker could cause the client to execute
arbitrary Java script commands.
For the stable distribution (woody) this problem has been fixed in
version 1.3.11-4.2.
For the unstable distribution (sid) this problem has been fixed in
version 1.3.12-8.
We recommend that you upgrade your icecast-server package.


Solution : http://www.debian.org/security/2004/dsa-541
Risk factor : High';

if (description) {
 script_id(15378);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "541");
 script_cve_id("CVE-2004-0781");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA541] DSA-541-1 icecast-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-541-1 icecast-server");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'icecast-server', release: '3.0', reference: '1.3.11-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package icecast-server is vulnerable in Debian 3.0.\nUpgrade to icecast-server_1.3.11-4.2\n');
}
if (deb_check(prefix: 'icecast-server', release: '3.1', reference: '1.3.12-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package icecast-server is vulnerable in Debian 3.1.\nUpgrade to icecast-server_1.3.12-8\n');
}
if (deb_check(prefix: 'icecast-server', release: '3.0', reference: '1.3.11-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package icecast-server is vulnerable in Debian woody.\nUpgrade to icecast-server_1.3.11-4.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
