# This script was automatically generated from the SSA-2004-110-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New utempter packages are available for Slackware 9.1 and -current to
fix a security issue.  (Slackware 9.1 was the first version of Slackware
to use the libutempter library, and earlier versions of Slackware are
not affected by this issue)

The utempter package provides a utility and shared library that
allows terminal applications such as xterm and screen to update
/var/run/utmp and /var/log/wtmp without requiring root privileges.
Steve Grubb has identified an issue with utempter-0.5.2 where
under certain circumstances an attacker could cause it to
overwrite files through a symlink.  This has been addressed by
upgrading the utempter package to use Dmitry V. Levin\'s new
implementation of libutempter that does not have this bug.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0233

';
if (description) {
script_id(18769);
script_version("$Revision: 1.3 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-110-01");
script_summary("SSA-2004-110-01 utempter security update ");
name["english"] = "SSA-2004-110-01 utempter security update ";
script_name(english:name["english"]);
script_cve_id("CVE-2004-0233");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.1", pkgname: "utempter", pkgver: "1.1.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package utempter is vulnerable in Slackware 9.1
Upgrade to utempter-1.1.1-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "utempter", pkgver: "1.1.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package utempter is vulnerable in Slackware -current
Upgrade to utempter-1.1.1-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
