# This script was automatically generated from the SSA-2003-336-01b
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='[slackware-security]  Samba security problem fixed

The samba packages in Slackware 8.1 and 9.0 have been upgraded to
Samba 2.2.8a to fix a security problem.

All sites running samba should upgrade.  


';
if (description) {
script_id(18712);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-336-01b");
script_summary("SSA-2003-336-01b Samba security problem fixed");
name["english"] = "SSA-2003-336-01b Samba security problem fixed";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "samba", pkgver: "2.2.8a", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package samba is vulnerable in Slackware 8.1
Upgrade to samba-2.2.8a-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "samba", pkgver: "2.2.8a", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package samba is vulnerable in Slackware 9.0
Upgrade to samba-2.2.8a-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
