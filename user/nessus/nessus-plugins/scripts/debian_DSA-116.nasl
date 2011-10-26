# This script was automatically generated from the dsa-116
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Zorgon found several buffer overflows in cfsd, a daemon that pushes
encryption services into the Unix(tm) file system.  We are not yet
sure if these overflows can successfully be exploited to gain root
access to the machine running the CFS daemon.  However, since cfsd can
easily be forced to die, a malicious user can easily perform a denial
of service attack to it.
This problem has been fixed in version 1.3.3-8.1 for the stable Debian
distribution and in version 1.4.1-5 for the testing and unstable
distribution of Debian.
We recommend that you upgrade your cfs package immediately.


Solution : http://www.debian.org/security/2002/dsa-116
Risk factor : High';

if (description) {
 script_id(14953);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "116");
 script_cve_id("CVE-2002-0351");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA116] DSA-116-1 cfs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-116-1 cfs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cfs', release: '2.2', reference: '1.3.3-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cfs is vulnerable in Debian 2.2.\nUpgrade to cfs_1.3.3-8.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
