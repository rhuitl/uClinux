# This script was automatically generated from the SSA-2006-257-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New openssl packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
10.2, and -current to fix a signature forgery security issue.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4339

As well as here:
  http://www.openssl.org/news/secadv_20060905.txt


';
if (description) {
script_id(22348);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-257-02");
script_summary("SSA-2006-257-02 openssl ");
name["english"] = "SSA-2006-257-02 openssl ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-4339","CVE-2006-4339");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "openssl-solibs", pkgver: "0.9.8b", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl-solibs is vulnerable in Slackware -current
Upgrade to openssl-solibs-0.9.8b-i486-2 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "openssl", pkgver: "0.9.8b", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl is vulnerable in Slackware -current
Upgrade to openssl-0.9.8b-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
