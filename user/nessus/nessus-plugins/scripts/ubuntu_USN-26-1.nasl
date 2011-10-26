# This script was automatically generated from the 26-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "bogofilter" is missing a security patch.

Description :

Antti-Juhani Kaijanaho discovered a Denial of Service vulnerability in
bogofilter. The quoted-printable decoder handled certain Base-64
encoded strings in an invalid way which caused a buffer overflow and
an immediate program abort.

The exact impact depends on the way bogofilter is integrated into the
system. In common setups, the mail that contains such malformed
headers is deferred by the mail delivery agent and remains in the
queue, where it will eventually bounce back to the sender.

Solution :

Upgrade to : 
- bogofilter-0.92.0-1ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20641);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "26-1");
script_summary(english:"bogofilter vulnerability");
script_name(english:"USN26-1 : bogofilter vulnerability");
script_cve_id("CVE-2004-1007");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "bogofilter", pkgver: "0.92.0-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package bogofilter-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to bogofilter-0.92.0-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
