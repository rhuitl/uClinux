# This script was automatically generated from the SSA-2003-251-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='

Upgraded inetd packages are available for Slackware 8.1, 9.0 and
- -current.  These fix a previously hard-coded limit of 256
connections-per-minute, after which the given service is disabled
for ten minutes.  An attacker could use a quick burst of
connections every ten minutes to effectively disable a service.

Once upon a time, this was an intentional feature of inetd, but in
today\'s world it has become a bug.  Even having inetd look at the
source IP and try to limit only the source of the attack would be
problematic since TCP source addresses are so easily faked.  So,
the approach we have taken (borrowed from FreeBSD) is to disable
this rate limiting "feature" by default.  It can be reenabled by
providing a -R <rate> option on the command-line if desired, but
for obvious reasons we do not recommend this.

Any site running services through inetd that they would like
protected from this simple DoS attack should upgrade to the new
inetd package immediately.


';
if (description) {
script_id(18736);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-251-01");
script_summary("SSA-2003-251-01 inetd DoS patched ");
name["english"] = "SSA-2003-251-01 inetd DoS patched ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "inetd", pkgver: "1.79s", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package inetd is vulnerable in Slackware 8.1
Upgrade to inetd-1.79s-i386-2 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "inetd", pkgver: "1.79s", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package inetd is vulnerable in Slackware 9.0
Upgrade to inetd-1.79s-i386-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "inetd", pkgver: "1.79s", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package inetd is vulnerable in Slackware -current
Upgrade to inetd-1.79s-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
