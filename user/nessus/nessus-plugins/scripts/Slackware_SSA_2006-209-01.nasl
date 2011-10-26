# This script was automatically generated from the SSA-2006-209-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New Apache packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
10.2, and -current to fix a security issue with mod_rewrite.

More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3747

In addition, new mod_ssl packages for Apache 1.3.37 are available for
all of these versions of Slackware.  This additional package does not
fix a security issue, but may be required on your system depending on
your Apache setup.


';
if (description) {
script_id(22152);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-209-01");
script_summary("SSA-2006-209-01 Apache httpd ");
name["english"] = "SSA-2006-209-01 Apache httpd ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-3747");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "apache", pkgver: "1.3.37", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware -current
Upgrade to apache-1.3.37-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "mod_ssl", pkgver: "2.8.28_1.3.37", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware -current
Upgrade to mod_ssl-2.8.28_1.3.37-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
