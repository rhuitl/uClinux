# This script was automatically generated from the 157-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- mozilla-enigmail 
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-enigmail 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-offline 
- mozilla-thunderbird-typeaheadfind 


Description :

Vladimir V. Perepelitsa discovered a bug in Thunderbird\'s handling of anonymous
functions during regular expression string replacement. A malicious HTML email
could exploit this to capture a random block of client memory. (CVE-2005-0989)

Georgi Guninski discovered that the types of certain XPInstall related
JavaScript objects were not sufficiently validated when they were called. This
could be exploited by malicious HTML email content to crash Thunderbird or even
execute arbitrary code with the privileges of the user. (CVE-2005-1159) 

Thunderbird did not properly verify the values of XML DOM nodes.  By tricking
the user to perform a common action like clicking on a link or opening the
context menu, a malicious HTML email could exploit this to execute arbitrary
JavaScript code with the full privileges of the user. (CVE-2005-1160)

A variant of the attack described in CVE-2005-1160 (see USN-124-1) was
discovered. Additional checks were added to make sure Javascript eval and
script objects are run with the p
[...]

Solution :

Upgrade to : 
- mozilla-enigmail-0.92-1ubuntu05.04.1 (Ubuntu 5.04)
- mozilla-thunderbird-1.0.6-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-thunderbird-dev-1.0.6-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-thunderbird-enigmail-0.92-1ubuntu05.04.1 (Ubuntu 5.04)
- mozilla-thunderbird-inspector-1.0.6-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-thunderbird-offline-1.0.6-0ubuntu05.04 (Ubuntu 5.04)
- mozilla-thunderbird-typeaheadfind-1.0.6-0ubuntu05.04 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20560);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "157-1");
script_summary(english:"mozilla-thunderbird vulnerabilities");
script_name(english:"USN157-1 : mozilla-thunderbird vulnerabilities");
script_cve_id("CVE-2005-0989","CVE-2005-1159","CVE-2005-1160","CVE-2005-1532","CVE-2005-2261","CVE-2005-2265","CVE-2005-2269","CVE-2005-2270","CVE-2005-2353");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "mozilla-enigmail", pkgver: "0.92-1ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-enigmail-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-enigmail-0.92-1ubuntu05.04.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird", pkgver: "1.0.6-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-1.0.6-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird-dev", pkgver: "1.0.6-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-dev-1.0.6-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird-enigmail", pkgver: "0.92-1ubuntu05.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-enigmail-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-enigmail-0.92-1ubuntu05.04.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.0.6-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-inspector-1.0.6-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird-offline", pkgver: "1.0.6-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-offline-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-offline-1.0.6-0ubuntu05.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.0.6-0ubuntu05.04");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-thunderbird-typeaheadfind-1.0.6-0ubuntu05.04
');
}

if (w) { security_hole(port: 0, data: desc); }
