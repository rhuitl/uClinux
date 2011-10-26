# This script was automatically generated from the dsa-231
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The Internet Software Consortium discovered several vulnerabilities
during an audit of the ISC DHCP Daemon.  The vulnerabilities exist in
error handling routines within the minires library and may be
exploitable as stack overflows.  This could allow a remote attacker to
execute arbitrary code under the user id the dhcpd runs under, usually
root.  Other DHCP servers than dhcp3 doesn\'t seem to be affected.
For the stable distribution (woody) this problem has been
fixed in version 3.0+3.0.1rc9-2.1.
The old stable distribution (potato) does not contain dhcp3 packages.
For the unstable distribution (sid) this problem has been fixed in
version 3.0+3.0.1rc11-1.
We recommend that you upgrade your dhcp3-server package.


Solution : http://www.debian.org/security/2003/dsa-231
Risk factor : High';

if (description) {
 script_id(15068);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "231");
 script_cve_id("CVE-2003-0026");
 script_xref(name: "CERT", value: "284857");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA231] DSA-231-1 dhcp3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-231-1 dhcp3");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dhcp3-client', release: '3.0', reference: '3.0+3.0.1rc9-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3-client is vulnerable in Debian 3.0.\nUpgrade to dhcp3-client_3.0+3.0.1rc9-2.1\n');
}
if (deb_check(prefix: 'dhcp3-common', release: '3.0', reference: '3.0+3.0.1rc9-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3-common is vulnerable in Debian 3.0.\nUpgrade to dhcp3-common_3.0+3.0.1rc9-2.1\n');
}
if (deb_check(prefix: 'dhcp3-dev', release: '3.0', reference: '3.0+3.0.1rc9-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3-dev is vulnerable in Debian 3.0.\nUpgrade to dhcp3-dev_3.0+3.0.1rc9-2.1\n');
}
if (deb_check(prefix: 'dhcp3-relay', release: '3.0', reference: '3.0+3.0.1rc9-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3-relay is vulnerable in Debian 3.0.\nUpgrade to dhcp3-relay_3.0+3.0.1rc9-2.1\n');
}
if (deb_check(prefix: 'dhcp3-server', release: '3.0', reference: '3.0+3.0.1rc9-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3-server is vulnerable in Debian 3.0.\nUpgrade to dhcp3-server_3.0+3.0.1rc9-2.1\n');
}
if (deb_check(prefix: 'dhcp3', release: '3.1', reference: '3.0+3.0.1rc11-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3 is vulnerable in Debian 3.1.\nUpgrade to dhcp3_3.0+3.0.1rc11-1\n');
}
if (deb_check(prefix: 'dhcp3', release: '3.0', reference: '3.0+3.0.1rc9-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3 is vulnerable in Debian woody.\nUpgrade to dhcp3_3.0+3.0.1rc9-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
