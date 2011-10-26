# This script was automatically generated from the 129-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- squid 
- squid-cgi 
- squid-common 
- squidclient 


Description :

It was discovered that Squid did not verify the validity of DNS server
responses. When Squid is started, it opens a DNS client UDP port whose
number is randomly assigned by the operating system. Unless your
network firewall is configured to accept DNS responses only from known
good nameservers, this vulnerability allowed users within the local
network to inject arbitrary DNS responses into Squid ("DNS spoofing").
This could be used to present different web pages to users from those
they actually requested.

Solution :

Upgrade to : 
- squid-2.5.8-3ubuntu1.2 (Ubuntu 5.04)
- squid-cgi-2.5.8-3ubuntu1.2 (Ubuntu 5.04)
- squid-common-2.5.8-3ubuntu1.2 (Ubuntu 5.04)
- squidclient-2.5.8-3ubuntu1.2 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20519);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "129-1");
script_summary(english:"squid vulnerability");
script_name(english:"USN129-1 : squid vulnerability");
script_cve_id("CVE-2005-1519");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "squid", pkgver: "2.5.8-3ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squid-2.5.8-3ubuntu1.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "squid-cgi", pkgver: "2.5.8-3ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-cgi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squid-cgi-2.5.8-3ubuntu1.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "squid-common", pkgver: "2.5.8-3ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squid-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squid-common-2.5.8-3ubuntu1.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "squidclient", pkgver: "2.5.8-3ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package squidclient-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to squidclient-2.5.8-3ubuntu1.2
');
}

if (w) { security_hole(port: 0, data: desc); }
