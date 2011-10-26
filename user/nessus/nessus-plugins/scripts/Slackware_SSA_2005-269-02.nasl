# This script was automatically generated from the SSA-2005-269-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New X.Org server packages are available for Slackware 10.0, 10.1, 10.2,
and -current to fix a security issue.  An integer overflow in the pixmap
handling code may allow the execution of arbitrary code through a
specially crafted pixmap.  Slackware 10.2 was patched against this
vulnerability before its release, but new server packages are being issued
for Slackware 10.2 and -current using an improved patch, as there were
some bug reports using certain programs.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2495


';
if (description) {
script_id(19867);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-269-02");
script_summary("SSA-2005-269-02 X.Org pixmap overflow ");
name["english"] = "SSA-2005-269-02 X.Org pixmap overflow ";
script_name(english:name["english"]);
script_cve_id("CVE-2005-2495");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.0", pkgname: "x11", pkgver: "6.7.0", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11 is vulnerable in Slackware 10.0
Upgrade to x11-6.7.0-i486-5 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "x11-xnest", pkgver: "6.7.0", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xnest is vulnerable in Slackware 10.0
Upgrade to x11-xnest-6.7.0-i486-5 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "x11-xprt", pkgver: "6.7.0", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xprt is vulnerable in Slackware 10.0
Upgrade to x11-xprt-6.7.0-i486-5 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "x11-xvfb", pkgver: "6.7.0", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xvfb is vulnerable in Slackware 10.0
Upgrade to x11-xvfb-6.7.0-i486-5 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "x11", pkgver: "6.8.1", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11 is vulnerable in Slackware 10.1
Upgrade to x11-6.8.1-i486-4 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "x11-xdmx", pkgver: "6.8.1", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xdmx is vulnerable in Slackware 10.1
Upgrade to x11-xdmx-6.8.1-i486-4 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "x11-xnest", pkgver: "6.8.1", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xnest is vulnerable in Slackware 10.1
Upgrade to x11-xnest-6.8.1-i486-4 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "x11-xvfb", pkgver: "6.8.1", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xvfb is vulnerable in Slackware 10.1
Upgrade to x11-xvfb-6.8.1-i486-4 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "x11", pkgver: "6.8.2", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11 is vulnerable in Slackware 10.2
Upgrade to x11-6.8.2-i486-4 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "x11-xdmx", pkgver: "6.8.2", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xdmx is vulnerable in Slackware 10.2
Upgrade to x11-xdmx-6.8.2-i486-4 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "x11-xnest", pkgver: "6.8.2", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xnest is vulnerable in Slackware 10.2
Upgrade to x11-xnest-6.8.2-i486-4 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "x11-xvfb", pkgver: "6.8.2", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xvfb is vulnerable in Slackware 10.2
Upgrade to x11-xvfb-6.8.2-i486-4 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "x11", pkgver: "6.8.2", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11 is vulnerable in Slackware -current
Upgrade to x11-6.8.2-i486-4 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "x11-xdmx", pkgver: "6.8.2", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xdmx is vulnerable in Slackware -current
Upgrade to x11-xdmx-6.8.2-i486-4 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "x11-xnest", pkgver: "6.8.2", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xnest is vulnerable in Slackware -current
Upgrade to x11-xnest-6.8.2-i486-4 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "x11-xvfb", pkgver: "6.8.2", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xvfb is vulnerable in Slackware -current
Upgrade to x11-xvfb-6.8.2-i486-4 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
