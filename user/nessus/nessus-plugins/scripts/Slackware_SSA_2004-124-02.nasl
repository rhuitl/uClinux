# This script was automatically generated from the SSA-2004-124-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New sysklogd packages are available for Slackware 8.1, 9.0, 9.1, and -current
to fix a security issue where a user could cause syslogd to crash.  Thanks to
Steve Grubb who researched the issue.

';
if (description) {
script_id(18756);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-124-02");
script_summary("SSA-2004-124-02 sysklogd update ");
name["english"] = "SSA-2004-124-02 sysklogd update ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "sysklogd", pkgver: "1.4.1", pkgnum:  "7", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sysklogd is vulnerable in Slackware 8.1
Upgrade to sysklogd-1.4.1-i386-7 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "sysklogd", pkgver: "1.4.1", pkgnum:  "9", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sysklogd is vulnerable in Slackware 9.0
Upgrade to sysklogd-1.4.1-i386-9 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "sysklogd", pkgver: "1.4.1", pkgnum:  "9", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sysklogd is vulnerable in Slackware 9.1
Upgrade to sysklogd-1.4.1-i486-9 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "sysklogd", pkgver: "1.4.1", pkgnum:  "9", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sysklogd is vulnerable in Slackware -current
Upgrade to sysklogd-1.4.1-i486-9 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
