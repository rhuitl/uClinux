# This script was automatically generated from the SSA-2005-255-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New dhcpcd packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, and -current to fix a minor security issue.  The dhcpcd daemon
can be tricked into reading past the end of the DHCP buffer by a
malicious DHCP server, which causes the dhcpcd daemon to crash and
results in a denial of service.  Of course, a malicious DHCP server
could simply give you an IP address that wouldn\'t work, too, such as
127.0.0.1, but since people have been asking about this issue, here\'s
a fix, and that\'s the extent of the impact.  In other words, very
little real impact.

Even less detail about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1848

';
if (description) {
script_id(19864);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-255-01");
script_summary("SSA-2005-255-01 dhcpcd DoS ");
name["english"] = "SSA-2005-255-01 dhcpcd DoS ";
script_name(english:name["english"]);
script_cve_id("CVE-2005-1848");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package dhcpcd is vulnerable in Slackware 8.1
Upgrade to dhcpcd-1.3.22pl4-i386-2 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package dhcpcd is vulnerable in Slackware 9.0
Upgrade to dhcpcd-1.3.22pl4-i386-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package dhcpcd is vulnerable in Slackware 9.1
Upgrade to dhcpcd-1.3.22pl4-i486-2 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package dhcpcd is vulnerable in Slackware 10.0
Upgrade to dhcpcd-1.3.22pl4-i486-2 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package dhcpcd is vulnerable in Slackware 10.1
Upgrade to dhcpcd-1.3.22pl4-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "dhcpcd", pkgver: "1.3.22pl4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package dhcpcd is vulnerable in Slackware -current
Upgrade to dhcpcd-1.3.22pl4-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
