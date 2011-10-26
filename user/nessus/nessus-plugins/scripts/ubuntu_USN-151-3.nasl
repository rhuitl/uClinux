# This script was automatically generated from the 151-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "aide" is missing a security patch.

Description :

USN-148-1 and USN-151-1 fixed two security flaws in zlib, which could
be exploited to cause Denial of Service attacks or even arbitrary code
execution with malicious data streams.

Since aide is statically linked against the zlib library, it is also
affected by these issues. The updated packagages have been rebuilt
against the fixed zlib.

Solution :

Upgrade to : 
- aide-0.10-6.1ubuntu0.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20551);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "151-3");
script_summary(english:"aide vulnerabilities");
script_name(english:"USN151-3 : aide vulnerabilities");
script_cve_id("CVE-2005-1849","CVE-2005-2096");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "aide", pkgver: "0.10-6.1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package aide-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to aide-0.10-6.1ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
