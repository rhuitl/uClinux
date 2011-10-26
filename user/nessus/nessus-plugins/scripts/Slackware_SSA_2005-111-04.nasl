# This script was automatically generated from the SSA-2005-111-04
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New Mozilla packages are available for Slackware 10.0, 10.1, and -current
to fix various security issues and bugs.  See the Mozilla site for a complete
list of the issues patched:

  http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla

Also updated is Firefox in Slackware -current.

New versions of the mozilla-plugins symlink creation package are also out for
Slackware 10.0 and 10.1, and a new version of the jre-symlink package for
Slackware -current.


';
if (description) {
script_id(18806);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-111-04");
script_summary("SSA-2005-111-04 Mozilla/Firefox ");
name["english"] = "SSA-2005-111-04 Mozilla/Firefox ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.0", pkgname: "mozilla", pkgver: "1.7.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla is vulnerable in Slackware 10.0
Upgrade to mozilla-1.7.7-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "mozilla-plugins", pkgver: "1.7.7", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla-plugins is vulnerable in Slackware 10.0
Upgrade to mozilla-plugins-1.7.7-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "mozilla", pkgver: "1.7.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla is vulnerable in Slackware 10.1
Upgrade to mozilla-1.7.7-i486-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "mozilla-plugins", pkgver: "1.7.7", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla-plugins is vulnerable in Slackware 10.1
Upgrade to mozilla-plugins-1.7.7-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "jre-symlink", pkgver: "1.0.3", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package jre-symlink is vulnerable in Slackware -current
Upgrade to jre-symlink-1.0.3-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mozilla", pkgver: "1.7.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla is vulnerable in Slackware -current
Upgrade to mozilla-1.7.7-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mozilla-firefox", pkgver: "1.0.3", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mozilla-firefox is vulnerable in Slackware -current
Upgrade to mozilla-firefox-1.0.3-i686-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
