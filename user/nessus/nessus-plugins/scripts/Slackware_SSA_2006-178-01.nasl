# This script was automatically generated from the SSA-2006-178-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New kdebase packages are available for Slackware 10.0, 10.1, 10.2, and -current
to fix a security issue with KDM (the KDE login manager) which could be
exploited by a local attacker to read any file on the system.

The official KDE security advisory may be found here:
  http://www.kde.org/info/security/advisory-20060614-1.txt

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2449


';
if (description) {
script_id(21765);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-178-01");
script_summary("SSA-2006-178-01 kdebase kdm local file reading vulnerability ");
name["english"] = "SSA-2006-178-01 kdebase kdm local file reading vulnerability ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-2449");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "kdebase", pkgver: "3.5.3", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdebase is vulnerable in Slackware -current
Upgrade to kdebase-3.5.3-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
