# This script was automatically generated from the SSA-2003-141-05
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
An upgrade for mod_ssl to version 2.8.14_1.3.27 is now available.
This version provides RSA blinding by default which prevents an
extended timing analysis from revealing details of the secret key
to an attacker.  Note that this problem was already fixed within
OpenSSL, so this is a "double fix".  With this package, mod_ssl
is secured even if OpenSSL is not.

We recommend sites using mod_ssl upgrade to this new package.


';
if (description) {
script_id(18715);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-141-05");
script_summary("SSA-2003-141-05 mod_ssl RSA blinding fixes ");
name["english"] = "SSA-2003-141-05 mod_ssl RSA blinding fixes ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "mod_ssl", pkgver: "2.8.14_1.3.27", pkgnum:  "1", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mod_ssl is vulnerable in Slackware 9.0
Upgrade to mod_ssl-2.8.14_1.3.27-i386-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
