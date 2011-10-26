# This script was automatically generated from the SSA-2006-142-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New tetex packages are available for Slackware 10.2 and -current to
fix a possible security issue.  teTeX-3.0 incorporates some code from 
the xpdf program which has been shown to have various overflows that
could result in program crashes or possibly the execution of arbitrary
code as the teTeX user.  This is especially important to consider if
teTeX is being used as part of a printer filter.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3193


';
if (description) {
script_id(21583);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-142-01");
script_summary("SSA-2006-142-01 tetex PDF security ");
name["english"] = "SSA-2006-142-01 tetex PDF security ";
script_name(english:name["english"]);
script_cve_id("CVE-2005-3193");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "tetex", pkgver: "3.0", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package tetex is vulnerable in Slackware -current
Upgrade to tetex-3.0-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "tetex-doc", pkgver: "3.0", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package tetex-doc is vulnerable in Slackware -current
Upgrade to tetex-doc-3.0-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
