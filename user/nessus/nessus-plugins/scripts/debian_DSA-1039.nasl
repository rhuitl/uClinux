# This script was automatically generated from the dsa-1039
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in blender, a very fast
and versatile 3D modeller/renderer.  The Common Vulnerabilities and
Exposures Project identifies the following problems:
    Joxean Koret discovered that due to missing input validation a
    provided script is vulnerable to arbitrary command execution.
    Damian Put discovered a buffer overflow that allows remote
    attackers to cause a denial of service and possibly execute
    arbitrary code.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.36-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.40-1.
We recommend that you upgrade your blender package.


Solution : http://www.debian.org/security/2006/dsa-1039
Risk factor : High';

if (description) {
 script_id(22581);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1039");
 script_cve_id("CVE-2005-3302", "CVE-2005-4470");
 script_bugtraq_id(15981);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1039] DSA-1039-1 blender");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1039-1 blender");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'blender', release: '', reference: '2.40-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package blender is vulnerable in Debian .\nUpgrade to blender_2.40-1\n');
}
if (deb_check(prefix: 'blender', release: '3.1', reference: '2.36-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package blender is vulnerable in Debian 3.1.\nUpgrade to blender_2.36-1sarge1\n');
}
if (deb_check(prefix: 'blender', release: '3.1', reference: '2.36-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package blender is vulnerable in Debian sarge.\nUpgrade to blender_2.36-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
