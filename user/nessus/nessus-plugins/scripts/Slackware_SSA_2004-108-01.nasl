# This script was automatically generated from the SSA-2004-108-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
Upgraded tcpdump packages are available for Slackware 8.1, 9.0,
9.1, and -current to fix denial-of-service issues.  Sites using
tcpdump should upgrade to the new packages.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0183
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0184

The tcpdump advisory from Rapid7 may be found here:
  http://www.rapid7.com/advisories/R7-0017.html

';
if (description) {
script_id(18783);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-108-01");
script_summary("SSA-2004-108-01 tcpdump denial of service ");
name["english"] = "SSA-2004-108-01 tcpdump denial of service ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0183","CVE-2004-0184");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "tcpdump", pkgver: "3.8.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package tcpdump is vulnerable in Slackware 8.1
Upgrade to tcpdump-3.8.3-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "tcpdump", pkgver: "3.8.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package tcpdump is vulnerable in Slackware 9.0
Upgrade to tcpdump-3.8.3-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "tcpdump", pkgver: "3.8.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package tcpdump is vulnerable in Slackware 9.1
Upgrade to tcpdump-3.8.3-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "tcpdump", pkgver: "3.8.3", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package tcpdump is vulnerable in Slackware -current
Upgrade to tcpdump-3.8.3-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
