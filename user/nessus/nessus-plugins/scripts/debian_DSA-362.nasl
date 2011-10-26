# This script was automatically generated from the dsa-362
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
mindi, a program for creating boot/root disks, does not take
appropriate security precautions when creating temporary files.  This
bug could potentially be exploited to overwrite arbitrary files with
the privileges of the user running mindi.
For the stable distribution (woody) this problem has been fixed in
version 0.58.r5-1woody1.
For the unstable distribution (sid) this problem will be fixed soon.
Refer to Debian bug #203825.
We recommend that you update your mindi package.


Solution : http://www.debian.org/security/2003/dsa-362
Risk factor : High';

if (description) {
 script_id(15199);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "362");
 script_cve_id("CVE-2003-0617");
 script_bugtraq_id(8332);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA362] DSA-362-1 mindi");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-362-1 mindi");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mindi', release: '3.0', reference: '0.58.r5-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mindi is vulnerable in Debian 3.0.\nUpgrade to mindi_0.58.r5-1woody1\n');
}
if (deb_check(prefix: 'mindi', release: '3.0', reference: '0.58.r5-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mindi is vulnerable in Debian woody.\nUpgrade to mindi_0.58.r5-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
