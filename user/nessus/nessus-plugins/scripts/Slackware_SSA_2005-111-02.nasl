# This script was automatically generated from the SSA-2005-111-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New Python packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
and -current to fix a security issue in the SimpleXMLRPCServer library
module.


';
if (description) {
script_id(18811);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-111-02");
script_summary("SSA-2005-111-02 Python SimpleXMLRPCServer module ");
name["english"] = "SSA-2005-111-02 Python SimpleXMLRPCServer module ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "python", pkgver: "2.2.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware 8.1
Upgrade to python-2.2.3-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "python", pkgver: "2.2.3", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware 9.0
Upgrade to python-2.2.3-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "python", pkgver: "2.3.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware 9.1
Upgrade to python-2.3.5-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "python-demo", pkgver: "2.3.5", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-demo is vulnerable in Slackware 9.1
Upgrade to python-demo-2.3.5-noarch-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "python-tools", pkgver: "2.3.5", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-tools is vulnerable in Slackware 9.1
Upgrade to python-tools-2.3.5-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "python", pkgver: "2.3.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware 10.0
Upgrade to python-2.3.5-i486-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "python-demo", pkgver: "2.3.5", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-demo is vulnerable in Slackware 10.0
Upgrade to python-demo-2.3.5-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.0", pkgname: "python-tools", pkgver: "2.3.5", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-tools is vulnerable in Slackware 10.0
Upgrade to python-tools-2.3.5-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "python", pkgver: "2.4.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware 10.1
Upgrade to python-2.4.1-i486-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "python-demo", pkgver: "2.4.1", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-demo is vulnerable in Slackware 10.1
Upgrade to python-demo-2.4.1-noarch-1 or newer.
');
}
if (slackware_check(osver: "10.1", pkgname: "python-tools", pkgver: "2.4.1", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-tools is vulnerable in Slackware 10.1
Upgrade to python-tools-2.4.1-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "python", pkgver: "2.4.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python is vulnerable in Slackware -current
Upgrade to python-2.4.1-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "python-demo", pkgver: "2.4.1", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-demo is vulnerable in Slackware -current
Upgrade to python-demo-2.4.1-noarch-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "python-tools", pkgver: "2.4.1", pkgnum:  "1", pkgarch: "noarch")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package python-tools is vulnerable in Slackware -current
Upgrade to python-tools-2.4.1-noarch-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
