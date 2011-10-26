# This script was automatically generated from the dsa-652
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in unarj, a non-free ARJ
unarchive utility.  The Common Vulnerabilities and Exposures Project
identifies the following vulnerabilities:
    A buffer overflow has been discovered when handling long file
    names contained in an archive.  An attacker could create a
    specially crafted archive which could cause unarj to crash or
    possibly execute arbitrary code when being extracted by a victim.
    A directory traversal vulnerability has been found so that an
    attacker could create a specially crafted archive which would
    create files in the parent directory when being extracted by a
    victim.  When used recursively, this vulnerability could be used
    to overwrite critical system files and programs.
For the stable distribution (woody) these problems have been fixed in
version 2.43-3woody1.
For the unstable distribution (sid) these problems don\'t apply since
unstable/non-free does not contain the unarj package.
We recommend that you upgrade your unarj package.


Solution : http://www.debian.org/security/2005/dsa-652
Risk factor : High';

if (description) {
 script_id(16236);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "652");
 script_cve_id("CVE-2004-0947", "CVE-2004-1027");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA652] DSA-652-1 unarj");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-652-1 unarj");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'unarj', release: '3.0', reference: '2.43-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unarj is vulnerable in Debian 3.0.\nUpgrade to unarj_2.43-3woody1\n');
}
if (deb_check(prefix: 'unarj', release: '3.0', reference: '2.43-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unarj is vulnerable in Debian woody.\nUpgrade to unarj_2.43-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
