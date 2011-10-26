# This script was automatically generated from the SSA-2006-178-03
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New aRts packages are available for Slackware 10.0, 10.1, 10.2, and -current
to fix a possible security issue with artswrapper.  The artswrapper program
and the artsd daemon can be used to gain root privileges if artswrapper is
setuid root and the system is running a 2.6.x kernel.  Note that artswrapper
is not setuid root on Slackware by default.  Some people have recommended
setting it that way online though, so it\'s at least worth warning about.
It\'s far safer to just add users to the audio group.

The official KDE security advisory may be found here:
  http://www.kde.org/info/security/advisory-20060614-2.txt

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2916


';
if (description) {
script_id(21767);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-178-03");
script_summary("SSA-2006-178-03 arts ");
name["english"] = "SSA-2006-178-03 arts ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-2916");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "arts", pkgver: "1.5.3", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package arts is vulnerable in Slackware -current
Upgrade to arts-1.5.3-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
