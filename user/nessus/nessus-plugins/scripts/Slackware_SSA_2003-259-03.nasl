# This script was automatically generated from the SSA-2003-259-03
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
Upgraded WU-FTPD packages are available for Slackware 9.0 and
- -current.  These fix a problem where an attacker could use a
specially crafted filename in conjunction with WU-FTPD\'s
conversion feature (mostly used to compress files, or produce tar
archives) to execute arbitrary commands on the server.

In addition, a MAIL_ADMIN which has been found to be insecure has
been disabled.

We do not recommend deploying WU-FTPD in situations where security
is required.


';
if (description) {
script_id(18726);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-259-03");
script_summary("SSA-2003-259-03 WU-FTPD Security Advisory ");
name["english"] = "SSA-2003-259-03 WU-FTPD Security Advisory ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "wu-ftpd", pkgver: "2.6.2", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package wu-ftpd is vulnerable in Slackware 9.0
Upgrade to wu-ftpd-2.6.2-i386-3 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "wu-ftpd", pkgver: "2.6.2", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package wu-ftpd is vulnerable in Slackware -current
Upgrade to wu-ftpd-2.6.2-i486-3 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
