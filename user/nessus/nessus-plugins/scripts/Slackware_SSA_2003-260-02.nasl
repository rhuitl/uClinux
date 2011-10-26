# This script was automatically generated from the SSA-2003-260-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
The sendmail packages in Slackware 8.1, 9.0, and -current have been
patched to fix security problems.  These issues seem to be remotely
exploitable, so all sites running sendmail should upgrade right away.

Sendmail\'s 8.12.10 announcement may be found here:
  http://www.sendmail.org/8.12.10.html

';
if (description) {
script_id(18739);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-260-02");
script_summary("SSA-2003-260-02 Sendmail vulnerabilities fixed ");
name["english"] = "SSA-2003-260-02 Sendmail vulnerabilities fixed ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "sendmail", pkgver: "8.12.10", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sendmail is vulnerable in Slackware 8.1
Upgrade to sendmail-8.12.10-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "sendmail-cf", pkgver: "8.12.10", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sendmail-cf is vulnerable in Slackware 8.1
Upgrade to sendmail-cf-8.12.10-noarch-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "sendmail", pkgver: "8.12.10", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sendmail is vulnerable in Slackware 9.0
Upgrade to sendmail-8.12.10-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "sendmail-cf", pkgver: "8.12.10", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sendmail-cf is vulnerable in Slackware 9.0
Upgrade to sendmail-cf-8.12.10-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "sendmail", pkgver: "8.12.10", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sendmail is vulnerable in Slackware -current
Upgrade to sendmail-8.12.10-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "sendmail-cf", pkgver: "8.12.10", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sendmail-cf is vulnerable in Slackware -current
Upgrade to sendmail-cf-8.12.10-noarch-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
