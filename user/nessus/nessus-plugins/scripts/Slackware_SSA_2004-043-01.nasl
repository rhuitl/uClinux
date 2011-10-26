# This script was automatically generated from the SSA-2004-043-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
Mutt is a text-based program for reading electronic mail.

New mutt packages are available for Slackware 8.1, 9.0, 9.1,
and -current.  These have been upgraded to version 1.4.2i to
fix a buffer overflow that could lead to a machine compromise.
All sites using mutt should upgrade to the new mutt package.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0078


';
if (description) {
script_id(18772);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-043-01");
script_summary("SSA-2004-043-01 mutt security update ");
name["english"] = "SSA-2004-043-01 mutt security update ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0078");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "mutt", pkgver: "1.4.2i", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mutt is vulnerable in Slackware 8.1
Upgrade to mutt-1.4.2i-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "mutt", pkgver: "1.4.2i", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mutt is vulnerable in Slackware 9.0
Upgrade to mutt-1.4.2i-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "mutt", pkgver: "1.4.2i", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mutt is vulnerable in Slackware 9.1
Upgrade to mutt-1.4.2i-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mutt", pkgver: "1.4.2i", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mutt is vulnerable in Slackware -current
Upgrade to mutt-1.4.2i-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
