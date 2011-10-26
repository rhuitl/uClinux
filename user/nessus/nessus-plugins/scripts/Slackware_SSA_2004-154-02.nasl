# This script was automatically generated from the SSA-2004-154-02
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New PHP packages are available for Slackware 8.1, 9.0, 9.1, and -current
to fix a security issue.  These fix a problem in previous Slackware php
packages where linking PHP against a static library in an insecure path
(under /tmp) could allow a local attacker to place shared libraries at
this location causing PHP to crash, or to execute arbitrary code as the
PHP user (which is by default, "nobody").

Thanks to Bryce Nichols for researching and reporting this issue.


';
if (description) {
script_id(18778);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2004-154-02");
script_summary("SSA-2004-154-02 PHP local security issue ");
name["english"] = "SSA-2004-154-02 PHP local security issue ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "8.1", pkgname: "php", pkgver: "4.3.6", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 8.1
Upgrade to php-4.3.6-i386-1 or newer.
');
}
if (slackware_check(osver: "9.0", pkgname: "php", pkgver: "4.3.6", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 9.0
Upgrade to php-4.3.6-i386-1 or newer.
');
}
if (slackware_check(osver: "9.1", pkgname: "php", pkgver: "4.3.6", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware 9.1
Upgrade to php-4.3.6-i486-1 or newer.
');
}
if (slackware_check(osver: "-current", pkgname: "php", pkgver: "4.3.6", pkgnum:  "4", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package php is vulnerable in Slackware -current
Upgrade to php-4.3.6-i486-4 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
