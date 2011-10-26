# This script was automatically generated from the SSA-2006-130-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New Apache packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
10.2, and -current to fix a bug with Apache 1.3.35 and glibc that
breaks wildcards in Include directives.  It may not occur with all
versions of glibc, but it has been verified on -current (using an Include
within a file already Included causes a crash), so better to patch it
and reissue these packages just to be sure.  My apologies if the last
batch of updates caused anyone undue grief...  they worked here with my
(too simple?) config files.

Note that if you use mod_ssl, you\'ll also require the mod_ssl package
that was part of yesterday\'s release, and on -current you\'ll need the
newest PHP package (if you use PHP).

Thanks to Francesco Gringoli for bringing this issue to my attention.


';
if (description) {
script_id(21346);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-130-01");
script_summary("SSA-2006-130-01 Apache httpd redux ");
name["english"] = "SSA-2006-130-01 Apache httpd redux ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "apache", pkgver: "1.3.35", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package apache is vulnerable in Slackware -current
Upgrade to apache-1.3.35-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
