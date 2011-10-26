# This script was automatically generated from the 52-1 Ubuntu Security Notice
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

Ciaran McCreesh found several vulnerabilities related to the use of
options in Vim modeline commands, such as \'termcap\', \'printdevice\',
\'titleold\', \'filetype\', \'syntax\', \'backupext\', \'keymap\', \'patchmode\',
and \'langmenu\'.

If an attacker tricked an user to open a file with a specially crafted
modeline, he could exploit this to execute arbitrary commands with the
user\'s privileges.

Solution :

Upgrade to : 
- kvim-6.3-025+1ubuntu2.1 (Ubuntu 4.10)
- vim-6.3-025+1ubuntu2.1 (Ubuntu 4.10)
- vim-common-6.3-025+1ubuntu2.1 (Ubuntu 4.10)
- vim-doc-6.3-025+1ubuntu2.1 (Ubuntu 4.10)
- vim-gnome-6.3-025+1ubuntu2.1 (Ubuntu 4.10)
- vim-gtk-6.3-025+1ubuntu2.1 (Ubuntu 4.10)
- vim-lesstif-6.3-025+1ubuntu2.1 (Ubuntu 4.10)
- vim-perl-6.3-025+1ubuntu2.1 (Ubuntu 4.10)
- vim-python-6.3-025+1ubuntu2.1 (Ubuntu 4.10)
- vim-tcl-6.3-025+1ubuntu2.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20670);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "52-1");
script_summary(english:"vim vulnerability");
script_name(english:"USN52-1 : vim vulnerability");
script_cve_id("CVE-2004-1138");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "kvim", pkgver: "6.3-025+1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kvim-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to kvim-6.3-025+1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim", pkgver: "6.3-025+1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-6.3-025+1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-common", pkgver: "6.3-025+1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-common-6.3-025+1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-doc", pkgver: "6.3-025+1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-doc-6.3-025+1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-gnome", pkgver: "6.3-025+1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-gnome-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-gnome-6.3-025+1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-gtk", pkgver: "6.3-025+1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-gtk-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-gtk-6.3-025+1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-lesstif", pkgver: "6.3-025+1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-lesstif-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-lesstif-6.3-025+1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-perl", pkgver: "6.3-025+1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-perl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-perl-6.3-025+1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-python", pkgver: "6.3-025+1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-python-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-python-6.3-025+1ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "vim-tcl", pkgver: "6.3-025+1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package vim-tcl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to vim-tcl-6.3-025+1ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
