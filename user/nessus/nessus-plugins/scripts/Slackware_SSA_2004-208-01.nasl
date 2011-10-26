# This script was automatically generated from the SSA-2004-208-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
It was pointed out that the new Samba packages for Slackware 10.0
(and -current) have a dependency on libattr.so that wasn\'t in the previous
packages.  Since it\'s not the intent to introduce new requirements in
security patches (especially for stable versions), an alternate version
of the samba package is being made available that does not require
libattr.so.

The original samba-3.0.5-i486-1.tgz package for Slackware 10.0 will also
remain in the patches directory (at least for now, since it was just
referenced in a security advisory and the URL to it should remain working),
and because the original package works fine if the xfsprogs package (which
contains libattr) is installed.  If you\'re running a full installation or
have xfsprogs installed, you do not need to update samba again.


';
if (description) {
script_id(18764);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-208-01");
script_summary("SSA-2004-208-01 alternate samba package for Slackware 10.0 ");
name["english"] = "SSA-2004-208-01 alternate samba package for Slackware 10.0 ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.0", pkgname: "samba", pkgver: "3.0.5", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package samba is vulnerable in Slackware 10.0
Upgrade to samba-3.0.5-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "samba", pkgver: "3.0.5", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package samba is vulnerable in Slackware -current
Upgrade to samba-3.0.5-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
