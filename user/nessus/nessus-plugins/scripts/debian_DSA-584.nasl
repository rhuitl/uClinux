# This script was automatically generated from the dsa-584
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" noticed that the log functions in dhcp 2.x, which is
still distributed in the stable Debian release, contained pass
parameters to function that use format strings.  One use seems to be
exploitable in connection with a malicious DNS server.
For the stable distribution (woody) these problems have been fixed in
version 2.0pl5-11woody1.
For the unstable distribution (sid) these problems have been fixed in
version 2.0pl5-19.1.
We recommend that you upgrade your dhcp package.


Solution : http://www.debian.org/security/2004/dsa-584
Risk factor : High';

if (description) {
 script_id(15682);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "584");
 script_cve_id("CVE-2004-1006");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA584] DSA-584-1 dhcp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-584-1 dhcp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dhcp', release: '3.0', reference: '2.0pl5-11woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp is vulnerable in Debian 3.0.\nUpgrade to dhcp_2.0pl5-11woody1\n');
}
if (deb_check(prefix: 'dhcp-client', release: '3.0', reference: '2.0pl5-11woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp-client is vulnerable in Debian 3.0.\nUpgrade to dhcp-client_2.0pl5-11woody1\n');
}
if (deb_check(prefix: 'dhcp-relay', release: '3.0', reference: '2.0pl5-11woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp-relay is vulnerable in Debian 3.0.\nUpgrade to dhcp-relay_2.0pl5-11woody1\n');
}
if (deb_check(prefix: 'dhcp', release: '3.1', reference: '2.0pl5-19.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp is vulnerable in Debian 3.1.\nUpgrade to dhcp_2.0pl5-19.1\n');
}
if (deb_check(prefix: 'dhcp', release: '3.0', reference: '2.0pl5-11woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp is vulnerable in Debian woody.\nUpgrade to dhcp_2.0pl5-11woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
