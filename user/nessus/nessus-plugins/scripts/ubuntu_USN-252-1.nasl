# This script was automatically generated from the 252-1 Ubuntu Security Notice
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

Tavis Ormandy discovered a potential weakness in the signature
verification of gnupg. gpgv and gpg --verify returned a successful
exit code even if the checked file did not have any signature at all.
The recommended way of checking the result is to evaluate the status
messages, but some third party applications might just check the exit
code for determining whether or not a signature is valid. These
applications could be tricked into erroneously reporting a valid
signature.

Please note that this does not affect the Ubuntu package signature
checks.

Solution :

Upgrade to : 
- gnupg-1.4.1-1ubuntu1.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21071);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "252-1");
script_summary(english:"gnupg vulnerability");
script_name(english:"USN252-1 : gnupg vulnerability");
script_cve_id("CVE-2006-0455");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "gnupg", pkgver: "1.4.1-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gnupg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gnupg-1.4.1-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
