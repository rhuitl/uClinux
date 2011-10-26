# This script was automatically generated from the SSA-2004-077-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
Upgraded OpenSSL packages are available for Slackware 8.1, 9.0,
9.1, and -current.  These fix two potential denial-of-service
issues in earlier versions of OpenSSL.

We recommend sites that use OpenSSL upgrade to the fixed packages
right away.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0079
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0112

';
if (description) {
script_id(18785);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-077-01");
script_summary("SSA-2004-077-01 OpenSSL security update ");
name["english"] = "SSA-2004-077-01 OpenSSL security update ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0079","CVE-2004-0112");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "openssl", pkgver: "0.9.6m", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl is vulnerable in Slackware 8.1
Upgrade to openssl-0.9.6m-i386-1 or newer.
');
}
if (slackware_check(osver: "8.1", pkgname: "openssl-solibs", pkgver: "0.9.6m", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl-solibs is vulnerable in Slackware 8.1
Upgrade to openssl-solibs-0.9.6m-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "openssl", pkgver: "0.9.7d", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl is vulnerable in Slackware 9.0
Upgrade to openssl-0.9.7d-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "openssl-solibs", pkgver: "0.9.7d", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl-solibs is vulnerable in Slackware 9.0
Upgrade to openssl-solibs-0.9.7d-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "openssl", pkgver: "0.9.7d", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl is vulnerable in Slackware 9.1
Upgrade to openssl-0.9.7d-i486-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "openssl-solibs", pkgver: "0.9.7d", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl-solibs is vulnerable in Slackware 9.1
Upgrade to openssl-solibs-0.9.7d-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "openssl-solibs", pkgver: "0.9.7d", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl-solibs is vulnerable in Slackware -current
Upgrade to openssl-solibs-0.9.7d-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "openssl", pkgver: "0.9.7d", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package openssl is vulnerable in Slackware -current
Upgrade to openssl-0.9.7d-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
