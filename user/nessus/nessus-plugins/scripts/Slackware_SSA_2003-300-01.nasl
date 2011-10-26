# This script was automatically generated from the SSA-2003-300-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
GDM is the GNOME Display Manager, and is commonly used to provide
a graphical login for local users.

Upgraded gdm packages are available for Slackware 9.0, 9.1,
and -current.  These fix two vulnerabilities which could allow a local
user to crash or freeze gdm, preventing access to the machine until a
reboot.  Sites using gdm should upgrade, especially sites such as
computer labs that use gdm to provide public or semi-public access.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0793
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0794


';
if (description) {
script_id(18732);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-300-01");
script_summary("SSA-2003-300-01 gdm security update ");
name["english"] = "SSA-2003-300-01 gdm security update ";
script_name(english:name["english"]);
script_cve_id("CVE-2003-0793","CVE-2003-0794");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "gdm", pkgver: "2.4.1.7", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gdm is vulnerable in Slackware 9.0
Upgrade to gdm-2.4.1.7-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "gdm", pkgver: "2.4.4.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gdm is vulnerable in Slackware 9.1
Upgrade to gdm-2.4.4.5-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "gdm", pkgver: "2.4.4.5", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package gdm is vulnerable in Slackware -current
Upgrade to gdm-2.4.4.5-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
