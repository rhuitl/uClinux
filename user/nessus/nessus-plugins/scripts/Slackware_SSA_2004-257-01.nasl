# This script was automatically generated from the SSA-2004-257-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New samba packages are available for Slackware 10.0 and -current.
These fix two denial of service vulnerabilities reported by
iDEFENSE.  Slackware -current has been upgraded to samba-3.0.7,
while the samba-3.0.5 included with Slackware 10.0 has been
patched to fix these issues.  Sites running Samba 3.x should
upgrade to the new package.  Versions of Samba before 3.0.x are
not affected by these flaws.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0807
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0808


';
if (description) {
script_id(18757);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-257-01");
script_summary("SSA-2004-257-01 samba DoS ");
name["english"] = "SSA-2004-257-01 samba DoS ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0807","CVE-2004-0808");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.0", pkgname: "samba", pkgver: "3.0.5", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package samba is vulnerable in Slackware 10.0
Upgrade to samba-3.0.5-i486-3 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "samba", pkgver: "3.0.7", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package samba is vulnerable in Slackware -current
Upgrade to samba-3.0.7-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
