# This script was automatically generated from the dsa-846
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities have been discovered in cpio, a program to manage
archives of files.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Imran Ghory discovered a race condition in setting the file
    permissions of files extracted from cpio archives.  A local
    attacker with write access to the target directory could exploit
    this to alter the permissions of arbitrary files the extracting
    user has write permissions for.
    Imran Ghory discovered that cpio does not sanitise the path of
    extracted files even if the --no-absolute-filenames option was
    specified.  This can be exploited to install files in arbitrary
    locations where the extracting user has write permissions to.
For the old stable distribution (woody) these problems have been fixed in
version 2.4.2-39woody2.
For the stable distribution (sarge) these problems have been fixed in
version 2.5-1.3.
For the unstable distribution (sid) these problems have been fixed in
version 2.6-6.
We recommend that you upgrade your cpio package.


Solution : http://www.debian.org/security/2005/dsa-846
Risk factor : High';

if (description) {
 script_id(19954);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "846");
 script_cve_id("CVE-2005-1111", "CVE-2005-1229");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA846] DSA-846-1 cpio");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-846-1 cpio");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cpio', release: '', reference: '2.6-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cpio is vulnerable in Debian .\nUpgrade to cpio_2.6-6\n');
}
if (deb_check(prefix: 'cpio', release: '3.0', reference: '2.4.2-39woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cpio is vulnerable in Debian 3.0.\nUpgrade to cpio_2.4.2-39woody2\n');
}
if (deb_check(prefix: 'cpio', release: '3.1', reference: '2.5-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cpio is vulnerable in Debian 3.1.\nUpgrade to cpio_2.5-1.3\n');
}
if (deb_check(prefix: 'cpio', release: '3.1', reference: '2.5-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cpio is vulnerable in Debian sarge.\nUpgrade to cpio_2.5-1.3\n');
}
if (deb_check(prefix: 'cpio', release: '3.0', reference: '2.4.2-39woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cpio is vulnerable in Debian woody.\nUpgrade to cpio_2.4.2-39woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
