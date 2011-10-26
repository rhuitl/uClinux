# This script was automatically generated from the SSA-2004-014-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
INN (InterNetNews) is used to run a news (NNTP) server.

New INN packages are available for Slackware 9.0, 9.1, and -current.
These have been upgraded to inn-2.4.1 to fix a potentially
exploitable buffer overflow.  All sites running INN should upgrade.


';
if (description) {
script_id(18755);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-014-02");
script_summary("SSA-2004-014-02 INN security update ");
name["english"] = "SSA-2004-014-02 INN security update ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "inn", pkgver: "2.4.1", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package inn is vulnerable in Slackware 9.0
Upgrade to inn-2.4.1-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "inn", pkgver: "2.4.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package inn is vulnerable in Slackware 9.1
Upgrade to inn-2.4.1-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "inn", pkgver: "2.4.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package inn is vulnerable in Slackware -current
Upgrade to inn-2.4.1-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
