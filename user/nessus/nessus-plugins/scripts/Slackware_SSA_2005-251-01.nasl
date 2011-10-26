# This script was automatically generated from the SSA-2005-251-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New kdebase packages are available for Slackware 10.0, 10.1, and -current to
fix a security issue with the kcheckpass program.  Earlier versions of
Slackware are not affected.  A flaw in the way the program creates lockfiles
could allow a local attacker to gain root privileges.

For more details about the issue, see:

  http://www.kde.org/info/security/advisory-20050905-1.txt
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2494


';
if (description) {
script_id(19861);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-251-01");
script_summary("SSA-2005-251-01 kcheckpass in kdebase ");
name["english"] = "SSA-2005-251-01 kcheckpass in kdebase ";
script_name(english:name["english"]);
script_cve_id("CVE-2005-2494");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.0", pkgname: "kdebase", pkgver: "3.2.3", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdebase is vulnerable in Slackware 10.0
Upgrade to kdebase-3.2.3-i486-3 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "kdebase", pkgver: "3.3.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdebase is vulnerable in Slackware 10.1
Upgrade to kdebase-3.3.2-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kdebase", pkgver: "3.4.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdebase is vulnerable in Slackware -current
Upgrade to kdebase-3.4.2-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
