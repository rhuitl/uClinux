# This script was automatically generated from the 100-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- cdda2wav 
- cdrecord 
- cdrtools-doc 
- mkisofs 


Description :

Javier Fernández-Sanguino Peña noticed that cdrecord created temporary
files in an insecure manner if DEBUG was enabled in
/etc/cdrecord/rscsi. If the default value was used (which stored the
debug output file in /tmp), this could allow a symbolic link attack to
create or overwrite arbitrary files with the privileges of the user
invoking cdrecord.

Please note that DEBUG is not enabled by default in Ubuntu, so if you
did not explicitly enable it, this does not affect you.

Solution :

Upgrade to : 
- cdda2wav-2.0+a30.pre1-1ubuntu2.2 (Ubuntu 4.10)
- cdrecord-2.0+a30.pre1-1ubuntu2.2 (Ubuntu 4.10)
- cdrtools-doc-2.0+a30.pre1-1ubuntu2.2 (Ubuntu 4.10)
- mkisofs-2.0+a30.pre1-1ubuntu2.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20486);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "100-1");
script_summary(english:"cdrtools vulnerability");
script_name(english:"USN100-1 : cdrtools vulnerability");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "cdda2wav", pkgver: "2.0+a30.pre1-1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cdda2wav-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cdda2wav-2.0+a30.pre1-1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cdrecord", pkgver: "2.0+a30.pre1-1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cdrecord-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cdrecord-2.0+a30.pre1-1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cdrtools-doc", pkgver: "2.0+a30.pre1-1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cdrtools-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cdrtools-doc-2.0+a30.pre1-1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mkisofs", pkgver: "2.0+a30.pre1-1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mkisofs-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mkisofs-2.0+a30.pre1-1ubuntu2.2
');
}

if (w) { security_hole(port: 0, data: desc); }
