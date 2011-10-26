# This script was automatically generated from the dsa-128
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
fc found a buffer overflow in the variable expansion code
used by sudo for its prompt. Since sudo is necessarily installed suid
root a local user can use this to gain root access.
This has been fixed in version 1.6.2-2.2 for the stable distribution
of Debian and version 1.6.6-1 for the testing/unstable distribution.
We recommend that you upgrade your sudo package immediately.


Solution : http://www.debian.org/security/2002/dsa-128
Risk factor : High';

if (description) {
 script_id(14965);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "128");
 script_cve_id("CVE-2002-0184");
 script_bugtraq_id(4593);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA128] DSA-128-1 sudo");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-128-1 sudo");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sudo', release: '2.2', reference: '1.6.2p2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sudo is vulnerable in Debian 2.2.\nUpgrade to sudo_1.6.2p2-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
