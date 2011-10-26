# This script was automatically generated from a
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='New cvs packages are available to fix a security vulnerability.

';
if (description) {
script_id(18708);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_summary("SSA New CVS packages available");
name["english"] = "SSA- New CVS packages available";
script_name(english:name["english"]);script_cve_id("CVE-2003-0015");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "cvs", pkgver: "1.11.5", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package cvs is vulnerable in Slackware 8.1
Upgrade to cvs-1.11.5-i386-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "cvs", pkgver: "1.11.5", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package cvs is vulnerable in Slackware -current
Upgrade to cvs-1.11.5-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
