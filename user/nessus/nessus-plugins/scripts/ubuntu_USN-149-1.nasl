# This script was automatically generated from the 149-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- mozilla-firefox 
- mozilla-firefox-dev 
- mozilla-firefox-dom-inspector 
- mozilla-firefox-gnome-support 


Description :

Secunia.com reported that one of the recent security patches in
Firefox reintroduced the frame injection patch that was originally
known as CVE-2004-0718. This allowed a malicious web site to spoof the
contents of other web sites. (CVE-2005-1937)

In several places the browser user interface did not correctly
distinguish between true user events, such as mouse clicks or
keystrokes, and synthetic events genenerated by web content. This
could be exploited by malicious web sites to generate e. g. mouse
clicks that install malicious plugins. Synthetic events are now
prevented from reaching the browser UI entirely. (CVE-2005-2260)

Scripts in XBL controls from web content continued to be run even when
Javascript was disabled. This could be combined with most script-based
exploits to attack people running vulnerable versions who thought
disabling Javascript would protect them. (CVE-2005-2261)

Matthew Mastracci discovered a flaw in the addons installation
launcher. By forcing a page navigation immediately after ca
[...]

Solution :

Upgrade to : 
- mozilla-firefox-1.0.2-0ubuntu5.4 (Ubuntu 5.04)
- mozilla-firefox-dev-1.0.2-0ubuntu5.4 (Ubuntu 5.04)
- mozilla-firefox-dom-inspector-1.0.2-0ubuntu5.4 (Ubuntu 5.04)
- mozilla-firefox-gnome-support-1.0.2-0ubuntu5.4 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20544);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "149-1");
script_summary(english:"mozilla-firefox vulnerabilities");
script_name(english:"USN149-1 : mozilla-firefox vulnerabilities");
script_cve_id("CVE-2004-0718","CVE-2005-1937","CVE-2005-2260","CVE-2005-2261","CVE-2005-2263","CVE-2005-2264","CVE-2005-2265","CVE-2005-2266","CVE-2005-2267","CVE-2005-2268","CVE-2005-2269","CVE-2005-2270");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox", pkgver: "1.0.2-0ubuntu5.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-1.0.2-0ubuntu5.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dev", pkgver: "1.0.2-0ubuntu5.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dev-1.0.2-0ubuntu5.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dom-inspector", pkgver: "1.0.2-0ubuntu5.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dom-inspector-1.0.2-0ubuntu5.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-gnome-support", pkgver: "1.0.2-0ubuntu5.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-gnome-support-1.0.2-0ubuntu5.4
');
}

if (w) { security_hole(port: 0, data: desc); }
