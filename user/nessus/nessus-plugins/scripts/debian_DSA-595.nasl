# This script was automatically generated from the dsa-595
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Leon Juranic discovered that BNC, an IRC session bouncing proxy, does
not always protect buffers from being overwritten.  This could
exploited by a malicious IRC server to overflow a buffer of limited
size and execute arbitrary code on the client host.
For the stable distribution (woody) this problem has been fixed in
version 2.6.4-3.3.
This package does not exist in the testing or unstable distributions.
We recommend that you upgrade your bnc package.


Solution : http://www.debian.org/security/2004/dsa-595
Risk factor : High';

if (description) {
 script_id(15824);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "595");
 script_cve_id("CVE-2004-1052");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA595] DSA-595-1 bnc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-595-1 bnc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bnc', release: '3.0', reference: '2.6.4-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bnc is vulnerable in Debian 3.0.\nUpgrade to bnc_2.6.4-3.3\n');
}
if (deb_check(prefix: 'bnc', release: '3.0', reference: '2.6.4-3.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bnc is vulnerable in Debian woody.\nUpgrade to bnc_2.6.4-3.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
