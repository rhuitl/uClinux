# This script was automatically generated from the 68-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "enscript" is missing a security patch.

Description :

Erik Sjölund discovered several vulnerabilities in enscript which
could cause arbitrary code execution with the privileges of the user
calling enscript.

Quotes and other shell escape characters in titles and file names were
not handled in previous versions. (CVE-2004-1184)

Previous versions supported reading EPS data not only from a file, but
also from an arbitrary command pipe. Since checking for unwanted side
effects is infeasible, this feature has been disabled after
consultation with the authors of enscript. (CVE-2004-1185)

Finally, this update fixes two buffer overflows which were triggered by
certain input files. (CVE-2004-1186)

These issues can lead to privilege escalation if enscript is called
automatically from web server applications like viewcvs.

Solution :

Upgrade to : 
- enscript-1.6.4-4ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20688);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "68-1");
script_summary(english:"enscript vulnerabilities");
script_name(english:"USN68-1 : enscript vulnerabilities");
script_cve_id("CVE-2004-1184","CVE-2004-1185","CVE-2004-1186");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "enscript", pkgver: "1.6.4-4ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package enscript-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to enscript-1.6.4-4ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
