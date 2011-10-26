# This script was automatically generated from the SSA-2003-345-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
CVS is a client/server version control system.  As a server, it
is used to host source code repositories.  As a client, it is
used to access such repositories.  This advisory deals with the
use of CVS as a server.

A security problem which could allow an attacker to create
directories and possibly files outside of the CVS repository has
been fixed with the release of cvs-1.11.10.  Any sites running a
CVS server should upgrade to the new CVS package.


';
if (description) {
script_id(18735);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-345-01");
script_summary("SSA-2003-345-01 cvs security update ");
name["english"] = "SSA-2003-345-01 cvs security update ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "cvs", pkgver: "1.11.10", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package cvs is vulnerable in Slackware 8.1
Upgrade to cvs-1.11.10-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "cvs", pkgver: "1.11.10", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package cvs is vulnerable in Slackware 9.0
Upgrade to cvs-1.11.10-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "cvs", pkgver: "1.11.10", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package cvs is vulnerable in Slackware 9.1
Upgrade to cvs-1.11.10-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "cvs", pkgver: "1.11.10", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package cvs is vulnerable in Slackware -current
Upgrade to cvs-1.11.10-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
