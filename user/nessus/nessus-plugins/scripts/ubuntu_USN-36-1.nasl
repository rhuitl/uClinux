# This script was automatically generated from the 36-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- nfs-common 
- nfs-kernel-server 
- nhfsstone 


Description :

SGI discovered a remote Denial of Service vulnerability in the NFS
statd server. statd did not ignore the "SIGPIPE" signal which caused
it to shutdown if a misconfigured or malicious peer terminated the TCP
connection prematurely.

Solution :

Upgrade to : 
- nfs-common-1.0.6-3ubuntu1.1 (Ubuntu 4.10)
- nfs-kernel-server-1.0.6-3ubuntu1.1 (Ubuntu 4.10)
- nhfsstone-1.0.6-3ubuntu1.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20652);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "36-1");
script_summary(english:"nfs-utils vulnerability");
script_name(english:"USN36-1 : nfs-utils vulnerability");
script_cve_id("CVE-2004-1014");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "nfs-common", pkgver: "1.0.6-3ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nfs-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to nfs-common-1.0.6-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "nfs-kernel-server", pkgver: "1.0.6-3ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nfs-kernel-server-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to nfs-kernel-server-1.0.6-3ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "nhfsstone", pkgver: "1.0.6-3ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nhfsstone-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to nhfsstone-1.0.6-3ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
