# This script was automatically generated from the SSA-2006-129-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New mysql packages are available for Slackware 10.2 and -current to
fix security issues.  The MySQL package shipped with Slackware 10.2
may possibly leak sensitive information found in uninitialized
memory to authenticated users.  The MySQL package previously in
Slackware -current also suffered from these flaws, but an additional
overflow could allow arbitrary code execution.

Since the vulnerabilities require a valid login and/or access to the
database server, the risk is moderate.  Slackware does not provide
network access to a MySQL database by default.


More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database.
Issues that affect both Slackware 10.2 and -current:
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1516
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1517

An issue affecting only Slackware -current:
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1518


';
if (description) {
script_id(21345);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-129-02");
script_summary("SSA-2006-129-02 mysql ");
name["english"] = "SSA-2006-129-02 mysql ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-1516","CVE-2006-1517","CVE-2006-1518");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.2", pkgname: "mysql", pkgver: "4.1.19", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mysql is vulnerable in Slackware 10.2
Upgrade to mysql-4.1.19-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mysql", pkgver: "5.0.21", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mysql is vulnerable in Slackware -current
Upgrade to mysql-5.0.21-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
