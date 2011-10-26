# This script was automatically generated from the SSA-2003-195-01b
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New nfs-utils packages are available for Slackware 8.1, 9.0, and -current
to replace the ones that were issued yesterday.  A bug in has been fixed
in utils/mountd/auth.c that could cause mountd to crash.

';
if (description) {
script_id(18724);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-195-01b");
script_summary("SSA-2003-195-01b nfs-utils packages replaced ");
name["english"] = "SSA-2003-195-01b nfs-utils packages replaced ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "nfs-utils", pkgver: "1.0.4", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package nfs-utils is vulnerable in Slackware 8.1
Upgrade to nfs-utils-1.0.4-i386-2 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "nfs-utils", pkgver: "1.0.4", pkgnum:  "2", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package nfs-utils is vulnerable in Slackware 9.0
Upgrade to nfs-utils-1.0.4-i386-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "nfs-utils", pkgver: "1.0.4", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package nfs-utils is vulnerable in Slackware -current
Upgrade to nfs-utils-1.0.4-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
