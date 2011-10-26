# This script was automatically generated from the 113-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "libnet-ssleay-perl" is missing a security patch.

Description :

Javier Fernandez-Sanguino Pena discovered that this library used the
file /tmp/entropy as a fallback entropy source if a proper source was
not set in the environment variable EGD_PATH. This can potentially
lead to weakened cryptographic operations if an attacker provides a
/tmp/entropy file with known content.

The updated package requires the specification of an entropy source
with EGD_PATH and also requires that the source is a socket (as
opposed to a normal file).

Please note that this only affects systems which have egd installed
from third party sources; egd is not shipped with Ubuntu.

Solution :

Upgrade to : 
- libnet-ssleay-perl-1.25-1ubuntu0.2 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20500);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "113-1");
script_summary(english:"libnet-ssleay-perl vulnerability");
script_name(english:"USN113-1 : libnet-ssleay-perl vulnerability");
script_cve_id("CVE-2005-0106");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libnet-ssleay-perl", pkgver: "1.25-1ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libnet-ssleay-perl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libnet-ssleay-perl-1.25-1ubuntu0.2
');
}

if (w) { security_hole(port: 0, data: desc); }
