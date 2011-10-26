# This script was automatically generated from the SSA-2006-045-04
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New kdegraphics packages are available for Slackware 10.0, 10.1, 10.2,
and -current to fix security issues with kpdf.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3191
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3192
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3193
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3624
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3625
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3626
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3627
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3628
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0301

Additional information is also available from the KDE website:

  http://www.kde.org/info/security/advisory-20051207-2.txt
  http://www.kde.org/info/security/advisory-20060202-1.txt


';
if (description) {
script_id(20915);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-045-04");
script_summary("SSA-2006-045-04 kdegraphics ");
name["english"] = "SSA-2006-045-04 kdegraphics ";
script_name(english:name["english"]);
script_cve_id("CVE-2005-3191","CVE-2005-3192","CVE-2005-3193","CVE-2005-3624","CVE-2005-3625","CVE-2005-3626","CVE-2005-3627","CVE-2005-3628","CVE-2006-0301");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.0", pkgname: "kdegraphics", pkgver: "3.2.3", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdegraphics is vulnerable in Slackware 10.0
Upgrade to kdegraphics-3.2.3-i486-2 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "kdegraphics", pkgver: "3.3.2", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdegraphics is vulnerable in Slackware 10.1
Upgrade to kdegraphics-3.3.2-i486-4 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "kdegraphics", pkgver: "3.4.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdegraphics is vulnerable in Slackware 10.2
Upgrade to kdegraphics-3.4.2-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "kdegraphics", pkgver: "3.5.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package kdegraphics is vulnerable in Slackware -current
Upgrade to kdegraphics-3.5.1-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
