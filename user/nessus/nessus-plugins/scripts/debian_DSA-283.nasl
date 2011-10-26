# This script was automatically generated from the dsa-283
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ethan Benson discovered a problem in xfsdump, that contains
administrative utilities for the XFS filesystem.  When filesystem
quotas are enabled xfsdump runs xfsdq to save the quota information
into a file at the root of the filesystem being dumped.  The manner in
which this file is created is unsafe.
While fixing this, a new option &ldquo;-f path&rdquo; has been added to xfsdq(8)
to specify an output file instead of using the standard output stream.
This file is created by xfsdq and xfsdq will fail to run if it exists
already.  The file is also created with a more appropriate mode than
whatever the umask happened to be when xfsdump(8) was run.
For the stable distribution (woody) this problem has been fixed in
version 2.0.1-2.
The old stable distribution (potato) is not affected since it doesn\'t
contain xfsdump packages.
For the unstable distribution (sid) this problem has been fixed in
version 2.2.8-1.
We recommend that you upgrade your xfsdump package immediately.


Solution : http://www.debian.org/security/2003/dsa-283
Risk factor : High';

if (description) {
 script_id(15120);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "283");
 script_cve_id("CVE-2003-0173");
 script_bugtraq_id(7321);
 script_xref(name: "CERT", value: "111673");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA283] DSA-283-1 xfsdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-283-1 xfsdump");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xfsdump', release: '3.0', reference: '2.0.1-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfsdump is vulnerable in Debian 3.0.\nUpgrade to xfsdump_2.0.1-2\n');
}
if (deb_check(prefix: 'xfsdump', release: '3.1', reference: '2.2.8-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfsdump is vulnerable in Debian 3.1.\nUpgrade to xfsdump_2.2.8-1\n');
}
if (deb_check(prefix: 'xfsdump', release: '3.0', reference: '2.0.1-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfsdump is vulnerable in Debian woody.\nUpgrade to xfsdump_2.0.1-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
