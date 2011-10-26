# This script was automatically generated from the SSA-2006-207-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New x11 packages are available for Slackware 10.2 and -current to
fix security issues. 

More details about the issues may be found here:

  http://lists.freedesktop.org/archives/xorg-announce/2006-June/000100.html
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1861


';
if (description) {
script_id(22099);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-207-02");
script_summary("SSA-2006-207-02 x11 ");
name["english"] = "SSA-2006-207-02 x11 ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-1861");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "fontconfig", pkgver: "2.2.3", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package fontconfig is vulnerable in Slackware -current
Upgrade to fontconfig-2.2.3-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "freetype", pkgver: "2.1.9", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package freetype is vulnerable in Slackware -current
Upgrade to freetype-2.1.9-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "x11", pkgver: "6.9.0", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11 is vulnerable in Slackware -current
Upgrade to x11-6.9.0-i486-5 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "x11-devel", pkgver: "6.9.0", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-devel is vulnerable in Slackware -current
Upgrade to x11-devel-6.9.0-i486-5 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "x11-xdmx", pkgver: "6.9.0", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xdmx is vulnerable in Slackware -current
Upgrade to x11-xdmx-6.9.0-i486-5 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "x11-xnest", pkgver: "6.9.0", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xnest is vulnerable in Slackware -current
Upgrade to x11-xnest-6.9.0-i486-5 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "x11-xvfb", pkgver: "6.9.0", pkgnum:  "5", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package x11-xvfb is vulnerable in Slackware -current
Upgrade to x11-xvfb-6.9.0-i486-5 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
