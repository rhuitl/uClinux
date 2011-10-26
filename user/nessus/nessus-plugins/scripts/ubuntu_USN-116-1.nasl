# This script was automatically generated from the 116-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "gzip" is missing a security patch.

Description :

Imran Ghory discovered a race condition in the file permission restore
code of gzip and gunzip. While a user was compressing or decompressing
a file, a local attacker with write permissions in the directory of
that file could replace the target file with a hard link.  This would
cause gzip to restore the file permissions to the hard link target
instead of to the gzip output file, which could be exploited to gain
read or even write access to files of other users.  (CVE-2005-0988)

Ulf Harnhammar found a path traversal vulnerability when gunzip was
used with the -N option. An attacker could exploit this to create
files in an arbitrary directory with the permissions of a user if he
tricked this user to decompress a specially crafted gzip file using
the -N option (which can also happen in systems that automatically
process uploaded gzip files). (CVE-2005-1228)

Solution :

Upgrade to : 
- gzip-1.3.5-9ubuntu3.2 (Ubuntu 4.10)
- gzip-1.3.5-9ubuntu3.2 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20504);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "116-1");
script_summary(english:"gzip vulnerabilities");
script_name(english:"USN116-1 : gzip vulnerabilities");
script_cve_id("CVE-2005-0988","CVE-2005-1228");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "gzip", pkgver: "1.3.5-9ubuntu3.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gzip-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to gzip-1.3.5-9ubuntu3.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gzip", pkgver: "1.3.5-9ubuntu3.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gzip-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gzip-1.3.5-9ubuntu3.2
');
}

if (w) { security_hole(port: 0, data: desc); }
