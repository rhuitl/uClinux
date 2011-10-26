# This script was automatically generated from the 264-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "gnupg" is missing a security patch.

Description :

Tavis Ormandy discovered a flaw in gnupg\'s signature verification. In
some cases, certain invalid signature formats could cause gpg to
report a \'good signature\' result for auxiliary unsigned data which was
prepended or appended to the checked message part.

Solution :

Upgrade to : 
- gnupg-1.4.1-1ubuntu1.2 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21182);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "264-1");
script_summary(english:"gnupg vulnerability");
script_name(english:"USN264-1 : gnupg vulnerability");
script_cve_id("CVE-2006-0049");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "gnupg", pkgver: "1.4.1-1ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gnupg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gnupg-1.4.1-1ubuntu1.2
');
}

if (w) { security_hole(port: 0, data: desc); }
