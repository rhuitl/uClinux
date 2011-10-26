# This script was automatically generated from the dsa-070
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The netkit-telnet daemon contained in the telnetd package version
0.16-4potato1, which is shipped with
the "stable" (2.2, potato) distribution of Debian GNU/Linux, is vulnerable to an
exploitable overflow in its output handling.


The original bug was found by <scut@nb.in-berlin.de>, and announced to
bugtraq on Jul 18 2001. At that time, netkit-telnet versions after 0.14 were
not believed to be vulnerable.


On Aug 10 2001, zen-parse posted an advisory based on the same problem, for
all netkit-telnet versions below 0.17.


More details can be found on http://online.securityfocus.com/archive/1/203000.
As Debian uses the `telnetd\' user to run in.telnetd, this is not a remote
root compromise on Debian systems; however, the user `telnetd\' can be compromised.

We strongly advise you update your telnetd package to the versions
listed below.



Solution : http://www.debian.org/security/2001/dsa-070
Risk factor : High';

if (description) {
 script_id(14907);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "070");
 script_cve_id("CVE-2001-0554");
 script_bugtraq_id(3064);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA070] DSA-070-1 netkit-telnet");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-070-1 netkit-telnet");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'telnet', release: '2.2', reference: '0.16-4potato.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package telnet is vulnerable in Debian 2.2.\nUpgrade to telnet_0.16-4potato.2\n');
}
if (deb_check(prefix: 'telnetd', release: '2.2', reference: '0.16-4potato.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package telnetd is vulnerable in Debian 2.2.\nUpgrade to telnetd_0.16-4potato.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
