# This script was automatically generated from the SSA-2006-072-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
A new kdegraphics package is available for Slackware 10.1 to fix a
security issue.  A portion of the recent security patch was missing
in the version that was applied to kdegraphics-3.3.2 in Slackware
10.1.  Other versions of Slackware are not affected by this
specific missing patch issue.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0746


';
if (description) {
script_id(21074);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-072-01");
script_summary("SSA-2006-072-01 Slackware 10.1 kdegraphics ");
name["english"] = "SSA-2006-072-01 Slackware 10.1 kdegraphics ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-0746");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.1", pkgname: "kdegraphics", pkgver: "3.3.2", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdegraphics is vulnerable in Slackware 10.1
Upgrade to kdegraphics-3.3.2-i486-5 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
