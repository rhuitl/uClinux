# This script was automatically generated from the SSA-2005-283-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New xine-lib packages are available for Slackware 9.1, 10.0, 10.1, 10.2,
and -current to fix a security issue.  A format string bug may allow the
execution of arbitrary code as the user running a xine-lib linked
application.  The attacker must provide (by uploading or running a server)
specially crafted CDDB information and then get the user to play the
referenced audio CD.

The official Xine advisory may be found here:

  http://xinehq.de/index.php/security/XSA-2005-1


';
if (description) {
script_id(19952);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-283-01");
script_summary("SSA-2005-283-01 xine-lib ");
name["english"] = "SSA-2005-283-01 xine-lib ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.1", pkgname: "xine-lib", pkgver: "1rc4", pkgnum:  "2", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xine-lib is vulnerable in Slackware 9.1
Upgrade to xine-lib-1rc4-i686-2 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "xine-lib", pkgver: "1.0.3a", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xine-lib is vulnerable in Slackware 10.0
Upgrade to xine-lib-1.0.3a-i686-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "xine-lib", pkgver: "1.0.3a", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xine-lib is vulnerable in Slackware 10.1
Upgrade to xine-lib-1.0.3a-i686-1 or newer.
');
}
if (slackware_check(osver: "10.2", pkgname: "xine-lib", pkgver: "1.0.3a", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xine-lib is vulnerable in Slackware 10.2
Upgrade to xine-lib-1.0.3a-i686-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "xine-lib", pkgver: "1.0.3a", pkgnum:  "1", pkgarch: "i686")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package xine-lib is vulnerable in Slackware -current
Upgrade to xine-lib-1.0.3a-i686-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
