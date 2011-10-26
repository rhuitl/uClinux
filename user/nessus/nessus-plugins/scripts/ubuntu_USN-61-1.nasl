# This script was automatically generated from the 61-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- kvim 
- vim 
- vim-common 
- vim-doc 
- vim-gnome 
- vim-gtk 
- vim-lesstif 
- vim-perl 
- vim-python 
- vim-tcl 


Description :

Javier Fernández-Sanguino Peña noticed that the auxillary scripts
"tcltags" and "vimspell.sh" created temporary files in an insecure
manner. This could allow a symbolic link attack to create or overwrite
arbitrary files with the privileges of the user invoking the script
(either by calling it directly or by execution through vim).

Solution :

Upgrade to : 
- kvim-6.3-025+1ubuntu2.2 (Ubuntu 4.10)
- vim-6.3-025+1ubuntu2.2 (Ubuntu 4.10)
- vim-common-6.3-025+1ubuntu2.2 (Ubuntu 4.10)
- vim-doc-6.3-025+1ubuntu2.2 (Ubuntu 4.10)
- vim-gnome-6.3-025+1ubuntu2.2 (Ubuntu 4.10)
- vim-gtk-6.3-025+1ubuntu2.2 (Ubuntu 4.10)
- vim-lesstif-6.3-025+1ubuntu2.2 (Ubuntu 4.10)
- vim-perl-6.3-025+1ubuntu2.2 (Ubuntu 4.10)
- vim-python-6.3-025+1ubuntu2.2 (Ubuntu 4.10)
- vim-tcl-6.3-025+1ubuntu2.2 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20680);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "61-1");
script_summary(english:"vim vulnerabilities");
script_name(english:"USN61-1 : vim vulnerabilities");
script_cve_id("CVE-2005-0069");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "kvim", pkgver: "6.3-025+1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kvim-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to kvim-6.3-025+1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim", pkgver: "6.3-025+1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-6.3-025+1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-common", pkgver: "6.3-025+1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-common-6.3-025+1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-doc", pkgver: "6.3-025+1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-doc-6.3-025+1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-gnome", pkgver: "6.3-025+1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-gnome-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-gnome-6.3-025+1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-gtk", pkgver: "6.3-025+1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-gtk-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-gtk-6.3-025+1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-lesstif", pkgver: "6.3-025+1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-lesstif-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-lesstif-6.3-025+1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-perl", pkgver: "6.3-025+1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-perl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-perl-6.3-025+1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-python", pkgver: "6.3-025+1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-python-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-python-6.3-025+1ubuntu2.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-tcl", pkgver: "6.3-025+1ubuntu2.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-tcl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-tcl-6.3-025+1ubuntu2.2
');
}

if (w) { security_hole(port: 0, data: desc); }
