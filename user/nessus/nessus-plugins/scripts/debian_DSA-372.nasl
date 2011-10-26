# This script was automatically generated from the dsa-372
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Shaun Colley discovered a buffer overflow vulnerability in netris, a
network version of a popular puzzle game.  A netris client connecting
to an untrusted netris server could be sent an unusually long data
packet, which would be copied into a fixed-length buffer without
bounds checking.  This vulnerability could be exploited to gain the
privileges of the user running netris in client mode, if they connect
to a hostile netris server.
For the current stable distribution (woody) this problem has been fixed
in version 0.5-4woody1.
For the unstable distribution (sid) this problem is fixed in version
0.52-1.
We recommend that you update your netris package.


Solution : http://www.debian.org/security/2003/dsa-372
Risk factor : High';

if (description) {
 script_id(15209);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "372");
 script_cve_id("CVE-2003-0685");
 script_bugtraq_id(8400);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA372] DSA-372-1 netris");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-372-1 netris");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'netris', release: '3.0', reference: '0.5-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netris is vulnerable in Debian 3.0.\nUpgrade to netris_0.5-4woody1\n');
}
if (deb_check(prefix: 'netris', release: '3.1', reference: '0.52-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netris is vulnerable in Debian 3.1.\nUpgrade to netris_0.52-1\n');
}
if (deb_check(prefix: 'netris', release: '3.0', reference: '0.5-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netris is vulnerable in Debian woody.\nUpgrade to netris_0.5-4woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
