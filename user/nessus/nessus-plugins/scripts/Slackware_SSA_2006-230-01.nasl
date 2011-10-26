# This script was automatically generated from the SSA-2006-230-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New libtiff packages are available for Slackware 9.0, 9.1, 10.0, 10.1,
10.2, and -current to fix security issues.  These issues could be used
to crash programs linked to libtiff or possibly to execute code as the
program\'s user.

Thanks to Tavis Ormandy and the Google Security Team.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3459
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3460
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3461
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3462
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3463
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3464
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3465


';
if (description) {
script_id(22236);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-230-01");
script_summary("SSA-2006-230-01 libtiff ");
name["english"] = "SSA-2006-230-01 libtiff ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-3459","CVE-2006-3460","CVE-2006-3461","CVE-2006-3462","CVE-2006-3463","CVE-2006-3464","CVE-2006-3465");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "libtiff", pkgver: "3.8.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package libtiff is vulnerable in Slackware -current
Upgrade to libtiff-3.8.2-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
