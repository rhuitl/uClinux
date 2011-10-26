# This script was automatically generated from the 246-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- imagemagick 
- libmagick++6 
- libmagick++6-dev 
- libmagick++6c2 
- libmagick6 
- libmagick6-dev 
- perlmagick 


Description :

Florian Weimer discovered that the delegate code did not correctly
handle file names which embed shell commands (CVE-2005-4601). Daniel
Kobras found a format string vulnerability in the SetImageInfo()
function (CVE-2006-0082). By tricking a user into processing an image
file with a specially crafted file name, these two vulnerabilities
could be exploited to execute arbitrary commands with the user\'s
privileges. These vulnerability become particularly critical if
malicious images are sent as email attachments and the email client
uses imagemagick to convert/display the images (e. g. Thunderbird and
Gnus).

In addition, Eero Häkkinen reported a bug in the command line argument
processing of the \'display\' command. Arguments that contained
wildcards and were expanded to several files could trigger a heap
overflow. However, there is no known possiblity to exploit this
remotely. (http://bugs.debian.org/345595)

Solution :

Upgrade to : 
- imagemagick-6.2.3.4-1ubuntu1.1 (Ubuntu 5.10)
- libmagick++6-6.0.6.2-2.1ubuntu1.2 (Ubuntu 5.04)
- libmagick++6-dev-6.2.3.4-1ubuntu1.1 (Ubuntu 5.10)
- libmagick++6c2-6.2.3.4-1ubuntu1.1 (Ubuntu 5.10)
- libmagick6-6.2.3.4-1ubuntu1.1 (Ubuntu 5.10)
- libmagick6-dev-6.2.3.4-1ubuntu1.1 (Ubuntu 5.10)
- perlmagick-6.2.3.4-1ubuntu1.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21054);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "246-1");
script_summary(english:"imagemagick vulnerabilities");
script_name(english:"USN246-1 : imagemagick vulnerabilities");
script_cve_id("CVE-2005-4601","CVE-2006-0082");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "imagemagick", pkgver: "6.2.3.4-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package imagemagick-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to imagemagick-6.2.3.4-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libmagick++6", pkgver: "6.0.6.2-2.1ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick++6-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libmagick++6-6.0.6.2-2.1ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick++6-dev", pkgver: "6.2.3.4-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick++6-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick++6-dev-6.2.3.4-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick++6c2", pkgver: "6.2.3.4-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick++6c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick++6c2-6.2.3.4-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick6", pkgver: "6.2.3.4-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick6-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick6-6.2.3.4-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick6-dev", pkgver: "6.2.3.4-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libmagick6-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick6-dev-6.2.3.4-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "perlmagick", pkgver: "6.2.3.4-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package perlmagick-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to perlmagick-6.2.3.4-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
