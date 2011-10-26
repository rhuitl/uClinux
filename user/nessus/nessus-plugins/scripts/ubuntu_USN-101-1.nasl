# This script was automatically generated from the 101-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- telnet 
- telnetd 


Description :

A buffer overflow was discovered in the telnet client\'s handling of
the LINEMODE suboptions. By sending a specially constructed reply
containing a large number of SLC (Set Local Character) commands, a
remote attacker (i. e. a malicious telnet server) could execute
arbitrary commands with the privileges of the user running the telnet
client. (CVE-2005-0469)

Michal Zalewski discovered a Denial of Service vulnerability in the
telnet server (telnetd). A remote attacker could cause the telnetd
process to free an invalid pointer, which caused the server process to
crash, leading to a denial of service (inetd will disable the service
if telnetd crashed repeatedly), or possibly the execution of arbitrary
code with the privileges of the telnetd process (by default,
the \'telnetd\' user). Please note that the telnet server is not
officially supported by Ubuntu, it is in the "universe"
component. (CVE-2004-0911)

Solution :

Upgrade to : 
- telnet-0.17-24ubuntu0.1 (Ubuntu 4.10)
- telnetd-0.17-24ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20487);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "101-1");
script_summary(english:"netkit-telnet vulnerabilities");
script_name(english:"USN101-1 : netkit-telnet vulnerabilities");
script_cve_id("CVE-2004-0911","CVE-2005-0469");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "telnet", pkgver: "0.17-24ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package telnet-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to telnet-0.17-24ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "telnetd", pkgver: "0.17-24ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package telnetd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to telnetd-0.17-24ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
