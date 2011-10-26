# This script was automatically generated from the SSA-2005-310-05
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New PHP packages are available for Slackware 10.2 and -current to fix minor
security issues relating to the overwriting of the GLOBALS array.

It has been reported here that this new version of PHP also breaks
squirrelmail and probably some other things.  Given the vague nature of
the security report, it\'s possible that the cure might be worse than the
disease as far as this upgrade is concerned.  If you encounter problems,
you may wish to drop back to 4.4.0, and I believe that doing so is
relatively safe.  I understand at least some of the issues are fixed in
CVS already, so perhaps another maintainance release is not far off.

Thanks to Gerardo Exequiel Pozzi for bringing the issues with 4.4.1 to my
attention so that this additional information could be included here.


';
if (description) {
script_id(20152);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-310-05");
script_summary("SSA-2005-310-05 PHP ");
name["english"] = "SSA-2005-310-05 PHP ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "10.2", pkgname: "php", pkgver: "4.4.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 10.2
Upgrade to php-4.4.1-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "php", pkgver: "4.4.1", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware -current
Upgrade to php-4.4.1-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
