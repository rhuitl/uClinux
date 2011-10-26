# This script was automatically generated from the 159-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "unzip" is missing a security patch.

Description :

If a ZIP archive contains binaries with the setuid and/or setgid bit
set, unzip preserved those bits when extracting the archive. This
could be exploited by tricking the administrator into unzipping an
archive with a setuid-root binary into a directory the attacker can
access.  This allowed the attacker to execute arbitrary commands with
root privileges.

The updated version does not preserve setuid, setgid, and sticky bits
any more by default. The old behaviour can be explicitly requested now
by supplying the option \'-K\'.

Solution :

Upgrade to : 
- unzip-5.51-2ubuntu1.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20563);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "159-1");
script_summary(english:"unzip vulnerability");
script_name(english:"USN159-1 : unzip vulnerability");
script_cve_id("CVE-2005-0602");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "unzip", pkgver: "5.51-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package unzip-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to unzip-5.51-2ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
