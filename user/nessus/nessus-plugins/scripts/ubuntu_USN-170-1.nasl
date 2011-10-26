# This script was automatically generated from the 170-1 Ubuntu Security Notice
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

Serge Mister and Robert Zuccherato discovered a weakness of the
symmetrical encryption algorithm of gnupg. When decrypting a message,
gnupg uses a feature called "quick scan"; this can quickly check
whether the key that is used for decryption is (probably) the right
one, so that wrong keys can be determined quickly without decrypting
the whole message.

A failure of the quick scan will be determined much faster than a
successful one.  Mister/Zuccherato demonstrated that this timing
difference can be exploited to an attack which allows an attacker to
decrypt parts of an encrypted message if an "oracle" is available, i.
e. an automatic system that receives random encrypted messages from
the attacker and answers whether it passes the quick scan check.

However, since the attack requires a huge amount of oracle answers
(about 32.000 for every 16 bytes of ciphertext), this attack is mostly
theoretical. It does not have any impact on human operation of gnupg
and is not believed to be exploitable in practice.

The 
[...]

Solution :

Upgrade to : 
- gnupg-1.2.5-3ubuntu5.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20577);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "170-1");
script_summary(english:"gnupg vulnerability");
script_name(english:"USN170-1 : gnupg vulnerability");
script_cve_id("CVE-2005-0366");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "gnupg", pkgver: "1.2.5-3ubuntu5.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gnupg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gnupg-1.2.5-3ubuntu5.1
');
}

if (w) { security_hole(port: 0, data: desc); }
