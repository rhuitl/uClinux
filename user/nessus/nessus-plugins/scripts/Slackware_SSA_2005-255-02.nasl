# This script was automatically generated from the SSA-2005-255-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New util-linux packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, and -current to fix a security issue with umount.  A bug in the
\'-r\' option could allow flags in /etc/fstab to be improperly dropped
on user-mountable volumes, allowing a user to gain root privileges.

For more details, see David Watson\'s post to BugTraq:

  http://www.securityfocus.com/archive/1/410333


';
if (description) {
script_id(19865);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-255-02");
script_summary("SSA-2005-255-02 util-linux umount privilege escalation ");
name["english"] = "SSA-2005-255-02 util-linux umount privilege escalation ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "util-linux", pkgver: "2.11r", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package util-linux is vulnerable in Slackware 8.1
Upgrade to util-linux-2.11r-i386-3 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "util-linux", pkgver: "2.11z", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package util-linux is vulnerable in Slackware 9.0
Upgrade to util-linux-2.11z-i386-2 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "util-linux", pkgver: "2.12", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package util-linux is vulnerable in Slackware 9.1
Upgrade to util-linux-2.12-i486-2 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "util-linux", pkgver: "2.12a", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package util-linux is vulnerable in Slackware 10.0
Upgrade to util-linux-2.12a-i486-2 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "util-linux", pkgver: "2.12p", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package util-linux is vulnerable in Slackware 10.1
Upgrade to util-linux-2.12p-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "util-linux", pkgver: "2.12p", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package util-linux is vulnerable in Slackware -current
Upgrade to util-linux-2.12p-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
