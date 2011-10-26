# This script was automatically generated from the dsa-715
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in the CVS server, which serves
the popular Concurrent Versions System.  The Common Vulnerability and
Exposures project identifies the following problems:
    Maks Polunin and Alberto Garcia discovered independently that
    using the pserver access method in connection with the repouid
    patch that Debian uses it is possible to bypass the password and
    gain access to the repository in question.
    Alberto Garcia discovered that a remote user can cause the cvs
    server to crash when the cvs-repouids file exists but does not
    contain a mapping for the current repository, which can be used as
    a denial of service attack.
For the stable distribution (woody) these problems have been fixed in
version 1.11.1p1debian-10.
For the unstable distribution (sid) these problems have been fixed in
version 1.12.9-11.
We recommend that you upgrade your cvs package.


Solution : http://www.debian.org/security/2005/dsa-715
Risk factor : High';

if (description) {
 script_id(18151);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "715");
 script_cve_id("CVE-2004-1342", "CVE-2004-1343");
 script_xref(name: "CERT", value: "327037");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA715] DSA-715-1 cvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-715-1 cvs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian 3.0.\nUpgrade to cvs_1.11.1p1debian-10\n');
}
if (deb_check(prefix: 'cvs', release: '3.1', reference: '1.12.9-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian 3.1.\nUpgrade to cvs_1.12.9-11\n');
}
if (deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian woody.\nUpgrade to cvs_1.11.1p1debian-10\n');
}
if (w) { security_hole(port: 0, data: desc); }
