# This script was automatically generated from the SSA-2005-203-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='

New kdenetwork packages are available for Slackware 10.0, 10.1, and -current
to fix security issues.  Overflows in libgadu (used by kopete) that can
cause a denial of service or arbitrary code execution.

More details about this vulnerability may be found here:
  http://www.kde.org/info/security/advisory-20050721-1.txt


';
if (description) {
script_id(19853);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-203-02");
script_summary("SSA-2005-203-02 kdenetwork ");
name["english"] = "SSA-2005-203-02 kdenetwork ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.0", pkgname: "kdenetwork", pkgver: "3.2.3", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdenetwork is vulnerable in Slackware 10.0
Upgrade to kdenetwork-3.2.3-i486-2 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "kdenetwork", pkgver: "3.3.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdenetwork is vulnerable in Slackware 10.1
Upgrade to kdenetwork-3.3.2-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kdenetwork", pkgver: "3.4.1", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdenetwork is vulnerable in Slackware -current
Upgrade to kdenetwork-3.4.1-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
