# This script was automatically generated from the 242-1 Ubuntu Security Notice
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

Aliet Santiesteban Sifontes discovered a remote Denial of Service
vulnerability in the attachment handler. An email with an attachment
whose filename contained invalid UTF-8 characters caused mailman to
crash. (CVE-2005-3573)

Mailman did not sufficiently verify the validity of email dates. Very
large numbers in dates caused mailman to crash. (CVE-2005-4153)

Solution :

Upgrade to : 
- mailman-2.1.5-8ubuntu2.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20789);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "242-1");
script_summary(english:"mailman vulnerabilities");
script_name(english:"USN242-1 : mailman vulnerabilities");
script_cve_id("CVE-2005-3573","CVE-2005-4153");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "mailman", pkgver: "2.1.5-8ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mailman-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mailman-2.1.5-8ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
