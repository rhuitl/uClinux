# This script was automatically generated from the SSA-2005-192-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='

Sorry folks, I mistakenly used a build template that was too new to
build the first round of PHP packages for Slackware 8.1, 9.0, and 9.1,
which tried to place the module in /usr/libexec/apache (older versions
of Slackware use /usr/libexec instead), and tried to link to incorrect
libraries and features.  These packages have been replaced with
working ones.  The packages for 10.0, 10.1, and -current were OK.


';
if (description) {
script_id(18797);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2005-192-02");
script_summary("SSA-2005-192-02 PHP packages updated again for 8.1, 9.0, 9.1 ");
name["english"] = "SSA-2005-192-02 PHP packages updated again for 8.1, 9.0, 9.1 ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "php", pkgver: "4.3.11", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 8.1
Upgrade to php-4.3.11-i386-3 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "php", pkgver: "4.3.11", pkgnum:  "3", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 9.0
Upgrade to php-4.3.11-i386-3 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "php", pkgver: "4.3.11", pkgnum:  "3", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 9.1
Upgrade to php-4.3.11-i486-3 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
