# This script was automatically generated from the SSA-2003-141-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New EPIC4 packages are available to fix security problems found
by Timo Sirainen.  EPIC4 is an IRC (Internet Relay Chat) client.
Under certain circumstances, a malicious IRC server could cause
EPIC4 to crash, or possibly to run arbitrary code as the user
running EPIC4.

All sites running EPIC4 are advised to upgrade.

More information on the problem can be found here:

';
if (description) {
script_id(18714);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-141-01");
script_summary("SSA-2003-141-01 EPIC4 security fixes ");
name["english"] = "SSA-2003-141-01 EPIC4 security fixes ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "epic4", pkgver: "1.0.1", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package epic4 is vulnerable in Slackware 8.1
Upgrade to epic4-1.0.1-i386-3 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "epic4", pkgver: "1.0.1", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package epic4 is vulnerable in Slackware 9.0
Upgrade to epic4-1.0.1-i386-3 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
