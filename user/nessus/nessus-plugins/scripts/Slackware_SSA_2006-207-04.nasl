# This script was automatically generated from the SSA-2006-207-04
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New xine-lib packages are available for Slackware 10.2 and -current to
fix security issues.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4048
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2802

';
if (description) {
script_id(22101);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-207-04");
script_summary("SSA-2006-207-04 xine-lib ");
name["english"] = "SSA-2006-207-04 xine-lib ";
script_name(english:name["english"]);
script_cve_id("CVE-2005-4048","CVE-2006-2802");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.2", pkgname: "xine-lib", pkgver: "1.1.2", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xine-lib is vulnerable in Slackware 10.2
Upgrade to xine-lib-1.1.2-i686-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "xine-lib", pkgver: "1.1.2", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xine-lib is vulnerable in Slackware -current
Upgrade to xine-lib-1.1.2-i686-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
