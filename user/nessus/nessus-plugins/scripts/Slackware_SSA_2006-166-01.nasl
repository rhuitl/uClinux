# This script was automatically generated from the SSA-2006-166-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New sendmail packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, 10.2, and -current to fix a possible denial-of-service issue.

Sendmail\'s complete advisory may be found here:
  http://www.sendmail.com/security/advisories/SA-200605-01.txt.asc

Sendmail has also provided an FAQ about this issue:
  http://www.sendmail.com/security/advisories/SA-200605-01/faq.shtml

The CVE entry for this issue may be found here:
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1173


';
if (description) {
script_id(21699);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-166-01");
script_summary("SSA-2006-166-01 sendmail ");
name["english"] = "SSA-2006-166-01 sendmail ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-1173");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "sendmail", pkgver: "8.13.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sendmail is vulnerable in Slackware -current
Upgrade to sendmail-8.13.7-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "sendmail-cf", pkgver: "8.13.7", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sendmail-cf is vulnerable in Slackware -current
Upgrade to sendmail-cf-8.13.7-noarch-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
