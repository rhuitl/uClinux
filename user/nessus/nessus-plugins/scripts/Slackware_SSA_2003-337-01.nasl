# This script was automatically generated from the SSA-2003-337-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
Rsync is a file transfer client and server.

A security problem which may lead to unauthorized machine access
or code execution has been fixed by upgrading to rsync-2.5.7.
This problem only affects machines running rsync in daemon mode,
and is easier to exploit if the non-default option "use chroot = no"
is used in the /etc/rsyncd.conf config file.

Any sites running an rsync server should upgrade immediately.

For complete information, see the rsync home page:

  http://rsync.samba.org

';
if (description) {
script_id(18734);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-337-01");
script_summary("SSA-2003-337-01 rsync security update ");
name["english"] = "SSA-2003-337-01 rsync security update ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "rsync", pkgver: "2.5.7", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package rsync is vulnerable in Slackware 8.1
Upgrade to rsync-2.5.7-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "rsync", pkgver: "2.5.7", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package rsync is vulnerable in Slackware 9.0
Upgrade to rsync-2.5.7-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "rsync", pkgver: "2.5.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package rsync is vulnerable in Slackware 9.1
Upgrade to rsync-2.5.7-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "rsync", pkgver: "2.5.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package rsync is vulnerable in Slackware -current
Upgrade to rsync-2.5.7-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
