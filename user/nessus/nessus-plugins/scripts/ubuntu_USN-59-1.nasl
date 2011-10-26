# This script was automatically generated from the 59-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "mailman" is missing a security patch.

Description :

Florian Weimer discovered a cross-site scripting vulnerability in
mailman\'s automatically generated error messages. An attacker could
craft an URL containing JavaScript (or other content embedded into
HTML) which triggered a mailman error page. When an unsuspecting user
followed this URL, the malicious content was copied unmodified to the
error page and executed in the context of this page.

Juha-Matti Tapio discovered an information disclosure in the private
rosters management. Everybody could check whether a specified email
address was subscribed to a private mailing list by looking at the
error message. This bug was Ubuntu/Debian specific.

Important note:

There is currently another known vulnerability: when an user
subscribes to a mailing list without choosing a password, mailman
automatically generates one. However, there are only about 5 million
different possible passwords which allows brute force attacks.

A different password generation algorithm already exists, but is
currently too immature to be
[...]

Solution :

Upgrade to : 
- mailman-2.1.5-1ubuntu2.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20677);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "59-1");
script_summary(english:"mailman vulnerabilities");
script_name(english:"USN59-1 : mailman vulnerabilities");
script_cve_id("CVE-2004-1177");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "mailman", pkgver: "2.1.5-1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mailman-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mailman-2.1.5-1ubuntu2.2
');
}

if (w) { security_hole(port: 0, data: desc); }
