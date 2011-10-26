# This script was automatically generated from the dsa-075
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The telnet daemon contained in the netkit-telnet-ssl_0.16.3-1 package in
the \'stable\' (potato) distribution of Debian GNU/Linux is vulnerable to an
exploitable overflow in its output handling.
The original bug was found by <scut@nb.in-berlin.de>, and announced to
bugtraq on Jul 18 2001. At that time, netkit-telnet versions after 0.14 were
not believed to be vulnerable.

On Aug 10 2001, zen-parse posted an advisory based on the same problem, for
all netkit-telnet versions below 0.17.

More details can be found on
SecurityFocus.
As Debian uses the \'telnetd\' user to run in.telnetd, this is not a remote
root compromise on Debian systems; the \'telnetd\' user can be compromised.

We strongly advise you update your netkit-telnet-ssl packages to the versions
listed below.



Solution : http://www.debian.org/security/2001/dsa-075
Risk factor : High';

if (description) {
 script_id(14912);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "075");
 script_cve_id("CVE-2001-0554");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA075] DSA-075-1 netkit-telnet-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-075-1 netkit-telnet-ssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ssltelnet', release: '2.2', reference: '0.16.3-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssltelnet is vulnerable in Debian 2.2.\nUpgrade to ssltelnet_0.16.3-1.1\n');
}
if (deb_check(prefix: 'telnet-ssl', release: '2.2', reference: '0.16.3-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package telnet-ssl is vulnerable in Debian 2.2.\nUpgrade to telnet-ssl_0.16.3-1.1\n');
}
if (deb_check(prefix: 'telnetd-ssl', release: '2.2', reference: '0.16.3-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package telnetd-ssl is vulnerable in Debian 2.2.\nUpgrade to telnetd-ssl_0.16.3-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
