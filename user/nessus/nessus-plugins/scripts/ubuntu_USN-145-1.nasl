# This script was automatically generated from the 145-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "wget" is missing a security patch.

Description :

Jan Minar discovered a path traversal vulnerability in wget. If the
name ".." was a valid host name (which can be achieved with a
malicious or poisoned domain name server), it was possible to trick
wget into creating downloaded files into arbitrary locations with
arbitrary names. For example, wget could silently overwrite the users
~/.bashrc and other configuration files which are executed
automatically. (CVE-2004-1487)

Jan Minar also discovered that wget printed HTTP response strings from
the server to the terminal without any filtering. Malicious HTTP
servers could exploit this to send arbitrary terminal sequences and
strings which would then be executed and printed to the console. This
could potentially lead to arbitrary code execution with the privileges
of the user invoking wget. (CVE-2004-1488)

Hugo Vázquez Caramés discovered a race condition when writing output
files. After wget determined the output file name, but before the file
was actually opened (the time window is determined by the delay of th
[...]

Solution :

Upgrade to : 
- wget-1.9.1-10ubuntu2.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20538);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "145-1");
script_summary(english:"wget vulnerabilities");
script_name(english:"USN145-1 : wget vulnerabilities");
script_cve_id("CVE-2004-1487","CVE-2004-1488","CVE-2004-2014");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "wget", pkgver: "1.9.1-10ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package wget-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to wget-1.9.1-10ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
