# This script was automatically generated from the SSA-2003-260-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
Upgraded OpenSSH 3.7.1p1 packages are available for Slackware
8.1, 9.0 and -current.  These fix additional buffer management
errors that were not corrected in the recent 3.7p1 release.
The possibility exists that these errors could allow a remote
exploit, so we recommend all sites running OpenSSH upgrade to
the new OpenSSH package immediately.


';
if (description) {
script_id(18727);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-260-01");
script_summary("SSA-2003-260-01 OpenSSH updated again ");
name["english"] = "SSA-2003-260-01 OpenSSH updated again ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "openssh", pkgver: "3.7.1p1", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssh is vulnerable in Slackware 8.1
Upgrade to openssh-3.7.1p1-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "openssh", pkgver: "3.7.1p1", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssh is vulnerable in Slackware 9.0
Upgrade to openssh-3.7.1p1-i386-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "openssh", pkgver: "3.7.1p1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssh is vulnerable in Slackware -current
Upgrade to openssh-3.7.1p1-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
