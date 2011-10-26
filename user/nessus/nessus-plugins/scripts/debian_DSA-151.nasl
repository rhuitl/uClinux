# This script was automatically generated from the dsa-151
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Solar Designer found a vulnerability in xinetd, a replacement for the
BSD derived inetd.  File descriptors for the signal pipe introduced in
version 2.3.4 are leaked into services started from xinetd.  The
descriptors could be used to talk to xinetd resulting in crashing it
entirely.  This is usually called a denial of service.
This problem has been fixed by the package maintainer in version
2.3.4-1.2 for the current stable distribution (woody) and in version
2.3.7-1 for the unstable distribution (sid).  The old stable
distribution (potato) is not affected, since it doesn\'t contain the
signal pipe.
We recommend that you upgrade your xinetd packages.


Solution : http://www.debian.org/security/2002/dsa-151
Risk factor : High';

if (description) {
 script_id(14988);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "151");
 script_cve_id("CVE-2002-0871");
 script_bugtraq_id(5458);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA151] DSA-151-1 xinetd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-151-1 xinetd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xinetd', release: '3.0', reference: '2.3.4-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xinetd is vulnerable in Debian 3.0.\nUpgrade to xinetd_2.3.4-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
