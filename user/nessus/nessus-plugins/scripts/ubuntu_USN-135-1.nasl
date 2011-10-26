# This script was automatically generated from the 135-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "gdb" is missing a security patch.

Description :

Tavis Ormandy found an integer overflow in the GNU debugger. By
tricking an user into merely load a specially crafted executable, an
attacker could exploit this to execute arbitrary code with the
privileges of the user running gdb. However, loading untrusted
binaries without actually executing them is rather uncommon, so the
risk of this flaw is low. (CVE-2005-1704)

Tavis Ormandy also discovered that gdb loads and executes the file
".gdbinit" in the current directory even if the file belongs to a
different user. By tricking an user into run gdb in a directory with a
malicious .gdbinit file, a local attacker could exploit this to run
arbitrary commands with the privileges of the user invoking gdb.
(CVE-2005-1705)

Solution :

Upgrade to : 
- gdb-6.3-5ubuntu1.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20526);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "135-1");
script_summary(english:"gdb vulnerabilities");
script_name(english:"USN135-1 : gdb vulnerabilities");
script_cve_id("CVE-2005-1704","CVE-2005-1705");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "gdb", pkgver: "6.3-5ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gdb-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gdb-6.3-5ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
