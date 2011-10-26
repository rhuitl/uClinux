# This script was automatically generated from the SSA-2005-195-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='

New XV image viewer packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, and -current to fix security issues.  Format string and other issues
could cause a crash or execution of arbitrary code if a specially crafted
image is loaded with XV.


';
if (description) {
script_id(19208);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-195-02");
script_summary("SSA-2005-195-02 XV ");
name["english"] = "SSA-2005-195-02 XV ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "xv", pkgver: "3.10a", pkgnum:  "4", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xv is vulnerable in Slackware 8.1
Upgrade to xv-3.10a-i386-4 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "xv", pkgver: "3.10a", pkgnum:  "4", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xv is vulnerable in Slackware 9.0
Upgrade to xv-3.10a-i386-4 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "xv", pkgver: "3.10a", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xv is vulnerable in Slackware 9.1
Upgrade to xv-3.10a-i486-4 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "xv", pkgver: "3.10a", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xv is vulnerable in Slackware 10.0
Upgrade to xv-3.10a-i486-4 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "xv", pkgver: "3.10a", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xv is vulnerable in Slackware 10.1
Upgrade to xv-3.10a-i486-4 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "xv", pkgver: "3.10a", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xv is vulnerable in Slackware -current
Upgrade to xv-3.10a-i486-4 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
