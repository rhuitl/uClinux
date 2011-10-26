# This script was automatically generated from the 158-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "gzip" is missing a security patch.

Description :

zgrep did not handle shell metacharacters like \'|\' and \'&\' properly
when they occurred in input file names. This could be exploited to
execute arbitrary commands with user privileges if zgrep is run in an
untrusted directory with specially crafted file names.

Solution :

Upgrade to : 
- gzip-1.3.5-9ubuntu3.4 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20562);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "158-1");
script_summary(english:"gzip vulnerability");
script_name(english:"USN158-1 : gzip vulnerability");
script_cve_id("CVE-2005-0758");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "gzip", pkgver: "1.3.5-9ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gzip-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gzip-1.3.5-9ubuntu3.4
');
}

if (w) { security_hole(port: 0, data: desc); }
