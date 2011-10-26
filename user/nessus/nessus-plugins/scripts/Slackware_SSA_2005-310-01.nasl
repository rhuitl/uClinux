# This script was automatically generated from the SSA-2005-310-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New curl packages are available for Slackware 9.1, 10.0, 10.1, 10.2,
and -current, and new wget packages are available for Slackware 8.1,
9.0, 9.1, 10.0, 10.1, 10.2, and -current.  These address a buffer
overflow in NTLM handling which may present a security problem, though
no public exploits are known at this time.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3185

';
if (description) {
script_id(20149);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-310-01");
script_summary("SSA-2005-310-01 curl/wget ");
name["english"] = "SSA-2005-310-01 curl/wget ";
script_name(english:name["english"]);
script_cve_id("CVE-2005-3185");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "wget", pkgver: "1.10.2", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package wget is vulnerable in Slackware 8.1
Upgrade to wget-1.10.2-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "wget", pkgver: "1.10.2", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package wget is vulnerable in Slackware 9.0
Upgrade to wget-1.10.2-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "curl", pkgver: "7.10.7", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package curl is vulnerable in Slackware 9.1
Upgrade to curl-7.10.7-i486-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "wget", pkgver: "1.10.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package wget is vulnerable in Slackware 9.1
Upgrade to wget-1.10.2-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "curl", pkgver: "7.12.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package curl is vulnerable in Slackware 10.0
Upgrade to curl-7.12.2-i486-2 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "wget", pkgver: "1.10.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package wget is vulnerable in Slackware 10.0
Upgrade to wget-1.10.2-i486-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "curl", pkgver: "7.12.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package curl is vulnerable in Slackware 10.1
Upgrade to curl-7.12.2-i486-2 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "wget", pkgver: "1.10.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package wget is vulnerable in Slackware 10.1
Upgrade to wget-1.10.2-i486-1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "curl", pkgver: "7.12.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package curl is vulnerable in Slackware 10.2
Upgrade to curl-7.12.2-i486-2 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "wget", pkgver: "1.10.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package wget is vulnerable in Slackware 10.2
Upgrade to wget-1.10.2-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "curl", pkgver: "7.12.2", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package curl is vulnerable in Slackware -current
Upgrade to curl-7.12.2-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "wget", pkgver: "1.10.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package wget is vulnerable in Slackware -current
Upgrade to wget-1.10.2-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
