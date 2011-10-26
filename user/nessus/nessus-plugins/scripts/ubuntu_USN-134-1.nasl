# This script was automatically generated from the 134-1 Ubuntu Security Notice
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

It was discovered that a malicious website could inject arbitrary
scripts into a target site by loading it into a frame and navigating
back to a previous Javascript URL that contained an eval() call. This
could be used to steal cookies or other confidential data from the
target site. If the target site is allowed to raise the install
confirmation dialog in Firefox then this flaw even allowed the
malicious site to execute arbitrary code with the privileges of the
Firefox user. By default only the Mozilla Update site is allowed to
attempt software installation; however, users can permit this for
additional sites.  (MFSA 2005-42)

Michael Krax, Georgi Guninski, and L. David Baron found that the
security checks that prevent script injection could be bypassed by
wrapping a javascript: url in another pseudo-protocol like
"view-source:" or "jar:".  (CVE-2005-1531)

A variant of the attack described in CVE-2005-1160 (see USN-124-1) was
discovered. Additional checks were added to make sure Javascript eval
and Script 
[...]

Solution :

Upgrade to : 
- mozilla-firefox-1.0.2-0ubuntu5.3 (Ubuntu 5.04)
- mozilla-firefox-dev-1.0.2-0ubuntu5.3 (Ubuntu 5.04)
- mozilla-firefox-dom-inspector-1.0.2-0ubuntu5.3 (Ubuntu 5.04)
- mozilla-firefox-gnome-support-1.0.2-0ubuntu5.3 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20525);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "134-1");
script_summary(english:"mozilla-firefox vulnerabilities");
script_name(english:"USN134-1 : mozilla-firefox vulnerabilities");
script_cve_id("CVE-2005-1160","CVE-2005-1531","CVE-2005-1532");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox", pkgver: "1.0.2-0ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-1.0.2-0ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dev", pkgver: "1.0.2-0ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dev-1.0.2-0ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dom-inspector", pkgver: "1.0.2-0ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dom-inspector-1.0.2-0ubuntu5.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-gnome-support", pkgver: "1.0.2-0ubuntu5.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-gnome-support-1.0.2-0ubuntu5.3
');
}

if (w) { security_hole(port: 0, data: desc); }
