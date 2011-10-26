# This script was automatically generated from the SSA-2004-278-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New zlib packages are available for Slackware 10.0 and -current to
fix a possible denial of service security issue.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-797

';
if (description) {
script_id(18745);
script_version("$Revision: 1.4 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-278-02");
script_summary("SSA-2004-278-02 zlib DoS ");
name["english"] = "SSA-2004-278-02 zlib DoS ";
script_name(english:name["english"]);
script_cve_id("CAN-2004-797");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.0", pkgname: "zlib", pkgver: "1.2.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package zlib is vulnerable in Slackware 10.0
Upgrade to zlib-1.2.2-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "zlib", pkgver: "1.2.2", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package zlib is vulnerable in Slackware -current
Upgrade to zlib-1.2.2-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
