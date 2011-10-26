# This script was automatically generated from the 285-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "awstats" is missing a security patch.

Description :

AWStats did not properly sanitize the \'migrate\' CGI parameter.  If the
update of the stats via web front-end is allowed, a remote attacker
could execute arbitrary commands on the server with the privileges of
the AWStats server.

This does not affect AWStats installations which only build static
pages.

Solution :

Upgrade to : 
- awstats-6.4-1ubuntu1.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21588);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "285-1");
script_summary(english:"awstats vulnerability");
script_name(english:"USN285-1 : awstats vulnerability");
script_cve_id("CVE-2006-2237");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "awstats", pkgver: "6.4-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package awstats-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to awstats-6.4-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
