# This script was automatically generated from the 70-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "libdbi-perl" is missing a security patch.

Description :

Javier Fernández-Sanguino Peña from the Debian Security Audit Project
discovered that the module DBI::ProxyServer in Perl\'s DBI library
created a PID file in an insecure manner. This could allow a symbolic
link attack to create or overwrite arbitrary files with the privileges
of the user invoking a program using this module (like \'dbiproxy\').

Now the module does not create a such a PID file by default.

Solution :

Upgrade to : 
- libdbi-perl-1.42-3ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20691);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "70-1");
script_summary(english:"libdbi-perl vulnerabilities");
script_name(english:"USN70-1 : libdbi-perl vulnerabilities");
script_cve_id("CVE-2005-0077");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libdbi-perl", pkgver: "1.42-3ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libdbi-perl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libdbi-perl-1.42-3ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
