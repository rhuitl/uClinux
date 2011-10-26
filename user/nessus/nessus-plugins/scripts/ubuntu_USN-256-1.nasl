# This script was automatically generated from the 256-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "bluez-hcidump" is missing a security patch.

Description :

Pierre Betouin discovered a Denial of Service vulnerability in the
handling of the L2CAP (Logical Link Control and Adaptation Layer
Protocol) layer. By sending a specially crafted L2CAP packet through a
wireless Bluetooth connection, a remote attacker could crash hcidump.

Since hcidump is mainly a debugging tool, the impact of this flaw is
very low.

Solution :

Upgrade to : 
- bluez-hcidump-1.23-0ubuntu1.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21064);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "256-1");
script_summary(english:"bluez-hcidump vulnerability");
script_name(english:"USN256-1 : bluez-hcidump vulnerability");
script_cve_id("CVE-2006-0670");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "bluez-hcidump", pkgver: "1.23-0ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package bluez-hcidump-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to bluez-hcidump-1.23-0ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
