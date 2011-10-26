# This script was automatically generated from the SSA-2004-207-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New mod_ssl packages are available for Slackware 8.1, 9.0, 9.1, 10.0
and -current to fix a security issue.  A format string vulnerability in
mod_proxy hook functions could allow an attacker to run code as the mod_ssl
user.  Sites using mod_ssl should upgrade (be sure to back up your existing
key files first).

';
if (description) {
script_id(18777);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-207-02");
script_summary("SSA-2004-207-02 new mod_ssl packages ");
name["english"] = "SSA-2004-207-02 new mod_ssl packages ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "mod_ssl", pkgver: "2.8.19_1.3.31", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 8.1
Upgrade to mod_ssl-2.8.19_1.3.31-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "mod_ssl", pkgver: "2.8.19_1.3.31", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 9.0
Upgrade to mod_ssl-2.8.19_1.3.31-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "mod_ssl", pkgver: "2.8.19_1.3.31", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 9.1
Upgrade to mod_ssl-2.8.19_1.3.31-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "mod_ssl", pkgver: "2.8.19_1.3.31", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 10.0
Upgrade to mod_ssl-2.8.19_1.3.31-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mod_ssl", pkgver: "2.8.19_1.3.31", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware -current
Upgrade to mod_ssl-2.8.19_1.3.31-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
