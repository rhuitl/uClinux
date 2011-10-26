# This script was automatically generated from the 197-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "shorewall" is missing a security patch.

Description :

A firewall bypass vulnerability has been found in shorewall. If
MACLIST_TTL was set to a value greater than 0 or MACLIST_DISPOSITION
was set to "ACCEPT" in /etc/shorewall/shorewall.conf, and a client was
positively identified through its MAC address, that client bypassed
all other policies/rules in place. This could allow external computers
to get access to ports that are intended to be restricted by the
firewall policy.

Please note that this does not affect the default configuration, which
does not enable MAC based client identification.

Solution :

Upgrade to : 
- shorewall-2.0.13-1ubuntu0.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20611);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "197-1");
script_summary(english:"shorewall vulnerability");
script_name(english:"USN197-1 : shorewall vulnerability");
script_cve_id("CVE-2005-2317");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "shorewall", pkgver: "2.0.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package shorewall-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to shorewall-2.0.13-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
