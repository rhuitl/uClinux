# This script was automatically generated from the 276-1 Ubuntu Security Notice
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

Igor Bukanov discovered that the JavaScript engine did not properly
declare some temporary variables. Under some rare circumstances, a
malicious mail with embedded JavaScript could exploit this to execute
arbitrary code with the privileges of the user.  (CVE-2006-0292,
CVE-2006-1742)

The function XULDocument.persist() did not sufficiently validate the
names of attributes. An attacker could exploit this to inject
arbitrary XML code into the file \'localstore.rdf\', which is read and
evaluated at startup. This could include JavaScript commands that
would be run with the user\'s privileges. (CVE-2006-0296)

Due to a flaw in the HTML tag parser a specific sequence of HTML tags
caused memory corruption. A malicious HTML email could exploit this to
crash the browser or even execute arbitrary code with the user\'s
privileges. (CVE-2006-0748)

An invalid ordering of table-related tags caused Thunderbird to use a
negative array index. A malicious HTML email could exploit this to
execute arbitrary code with the privi
[...]

Solution :

Upgrade to : 
- mozilla-enigmail-0.92.1-0ubuntu05.10.1 (Ubuntu 5.10)
- mozilla-thunderbird-1.0.8-0ubuntu05.10.1 (Ubuntu 5.10)
- mozilla-thunderbird-dev-1.0.8-0ubuntu05.10.1 (Ubuntu 5.10)
- mozilla-thunderbird-enigmail-0.92.1-0ubuntu05.10.1 (Ubuntu 5.10)
- mozilla-thunderbird-inspector-1.0.8-0ubuntu05.10.1 (Ubuntu 5.10)
- mozilla-thunderbird-offline-1.0.8-0ubuntu05.10.1 (Ubuntu 5.10)
- mozilla-thunderbird-typeaheadfind-1.0.8-0ubuntu05.10.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21321);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "276-1");
script_summary(english:"mozilla-thunderbird vulnerabilities");
script_name(english:"USN276-1 : mozilla-thunderbird vulnerabilities");
script_cve_id("CVE-2006-0292","CVE-2006-0296","CVE-2006-0748","CVE-2006-0749","CVE-2006-0884","CVE-2006-1045","CVE-2006-1727","CVE-2006-1728","CVE-2006-1730","CVE-2006-1731","CVE-2006-1732","CVE-2006-1733","CVE-2006-1734","CVE-2006-1735","CVE-2006-1737","CVE-2006-1738");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "mozilla-enigmail", pkgver: "0.92.1-0ubuntu05.10.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-enigmail-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-enigmail-0.92.1-0ubuntu05.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird", pkgver: "1.0.8-0ubuntu05.10.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-1.0.8-0ubuntu05.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-dev", pkgver: "1.0.8-0ubuntu05.10.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-dev-1.0.8-0ubuntu05.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-enigmail", pkgver: "0.92.1-0ubuntu05.10.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-enigmail-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-enigmail-0.92.1-0ubuntu05.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.0.8-0ubuntu05.10.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-inspector-1.0.8-0ubuntu05.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-offline", pkgver: "1.0.8-0ubuntu05.10.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-offline-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-offline-1.0.8-0ubuntu05.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.0.8-0ubuntu05.10.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-thunderbird-typeaheadfind-1.0.8-0ubuntu05.10.1
');
}

if (w) { security_hole(port: 0, data: desc); }
