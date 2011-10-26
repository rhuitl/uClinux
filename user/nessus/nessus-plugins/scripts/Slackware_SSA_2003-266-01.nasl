# This script was automatically generated from the SSA-2003-266-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
Upgraded OpenSSH 3.7.1p2 packages are available for Slackware 8.1,
9.0 and -current.  This fixes security problems with PAM
authentication.  It also includes several code cleanups from Solar
Designer.

Slackware is not vulnerable to the PAM problem, and it is not
believed that any of the other code cleanups fix exploitable
security problems, not nevertheless sites may wish to upgrade.

These are some of the more interesting entries from OpenSSH\'s
ChangeLog so you can be the judge:

     [buffer.c]
     protect against double free; #660;  zardoz at users.sf.net
   - markus@cvs.openbsd.org 2003/09/18 08:49:45
     [deattack.c misc.c session.c ssh-agent.c]
     more buffer allocation fixes; from Solar Designer; CVE-2003-0682;
     ok millert@
 - (djm) Bug #676: Fix PAM stack corruption
 - (djm) Fix bad free() in PAM code

';
if (description) {
script_id(18728);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-266-01");
script_summary("SSA-2003-266-01 New OpenSSH packages ");
name["english"] = "SSA-2003-266-01 New OpenSSH packages ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "openssh", pkgver: "3.7.1p2", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssh is vulnerable in Slackware 8.1
Upgrade to openssh-3.7.1p2-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "openssh", pkgver: "3.7.1p2", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssh is vulnerable in Slackware 9.0
Upgrade to openssh-3.7.1p2-i386-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "openssh", pkgver: "3.7.1p2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssh is vulnerable in Slackware -current
Upgrade to openssh-3.7.1p2-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
