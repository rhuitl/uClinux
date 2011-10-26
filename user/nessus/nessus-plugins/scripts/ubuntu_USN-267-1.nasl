# This script was automatically generated from the 267-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "mailman" is missing a security patch.

Description :

A remote Denial of Service vulnerability was discovered in the decoder
for multipart messages. Certain parts of type "message/delivery-status"
or parts containing only two blank lines triggered an exception. An
attacker could exploit this to crash Mailman by sending a
specially crafted email to a mailing list.

Solution :

Upgrade to : 
- mailman-2.1.5-8ubuntu2.2 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21184);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "267-1");
script_summary(english:"mailman vulnerability");
script_name(english:"USN267-1 : mailman vulnerability");
script_cve_id("CVE-2006-0052");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "mailman", pkgver: "2.1.5-8ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mailman-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mailman-2.1.5-8ubuntu2.2
');
}

if (w) { security_hole(port: 0, data: desc); }
