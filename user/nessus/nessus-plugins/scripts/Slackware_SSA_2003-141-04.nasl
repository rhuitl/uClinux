# This script was automatically generated from the SSA-2003-141-04
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
A key validation bug which results in all user IDs on a given key
being treated with the validity of the most-valid user ID on that
key has been fixed with the release of GnuPG 1.2.2.

We recommend sites using GnuPG upgrade to this new package.

For detailed information about the problem, see this page:
http://lists.gnupg.org/pipermail/gnupg-announce/2003q2/000268.html


';
if (description) {
script_id(18713);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-141-04");
script_summary("SSA-2003-141-04 GnuPG key validation fix ");
name["english"] = "SSA-2003-141-04 GnuPG key validation fix ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "gnupg", pkgver: "1.2.2", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gnupg is vulnerable in Slackware 9.0
Upgrade to gnupg-1.2.2-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
