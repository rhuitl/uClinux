# This script was automatically generated from the SSA-2004-240-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
A couple of bugs were found in the gaim 0.82 release, and gaim-0.82.1
was released to fix them.  In addition, gaim-encryption-2.29 did not
work with gaim-0.82 due to changes in the header files, so the
gaim-encryption plugin has also been updated to gaim-encryption-2.30.


';
if (description) {
script_id(18748);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-240-01");
script_summary("SSA-2004-240-01 gaim updated again ");
name["english"] = "SSA-2004-240-01 gaim updated again ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.1", pkgname: "gaim", pkgver: "0.82.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gaim is vulnerable in Slackware 9.1
Upgrade to gaim-0.82.1-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "gaim", pkgver: "0.82.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gaim is vulnerable in Slackware 10.0
Upgrade to gaim-0.82.1-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "gaim", pkgver: "0.82.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gaim is vulnerable in Slackware -current
Upgrade to gaim-0.82.1-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
