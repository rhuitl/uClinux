# This script was automatically generated from the SSA-2003-237-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
Upgraded infozip packages are available for Slackware 9.0 and -current.
These fix a security issue where a specially crafted archive may
overwrite files (including system files anywhere on the filesystem)
upon extraction by a user with sufficient permissions.

For more information, see:

http://www.securityfocus.com/bid/7550
http://lwn.net/Articles/38540/
http://xforce.iss.net/xforce/xfdb/12004
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0282


';
if (description) {
script_id(18722);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-237-01");
script_summary("SSA-2003-237-01 unzip vulnerability patched ");
name["english"] = "SSA-2003-237-01 unzip vulnerability patched ";
script_name(english:name["english"]);
script_cve_id("CVE-2003-0282");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "infozip", pkgver: "5.50", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package infozip is vulnerable in Slackware 9.0
Upgrade to infozip-5.50-i386-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "infozip", pkgver: "5.50", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package infozip is vulnerable in Slackware -current
Upgrade to infozip-5.50-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
