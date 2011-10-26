# This script was automatically generated from the dsa-752
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two problems have been discovered in gzip, the GNU compression
utility.  The Common Vulnerabilities and Exposures project identifies
the following problems.
    Imran Ghory discovered a race condition in the permissions setting
    code in gzip.  When decompressing a file in a directory an
    attacker has access to, gunzip could be tricked to set the file
    permissions to a different file the user has permissions to.
    Ulf Härnhammar discovered a path traversal vulnerability in
    gunzip.  When gunzip is used with the -N option an attacker could
    use
    this vulnerability to create files in an arbitrary directory with
    the permissions of the user.
For the oldstable distribution (woody) these problems have been fixed in
version 1.3.2-3woody5.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.5-10.
For the unstable distribution (sid) these problems have been fixed in
version 1.3.5-10.
We recommend that you upgrade your gzip package.


Solution : http://www.debian.org/security/2005/dsa-752
Risk factor : High';

if (description) {
 script_id(18673);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "752");
 script_cve_id("CVE-2005-0988", "CVE-2005-1228");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA752] DSA-752-1 gzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-752-1 gzip");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gzip', release: '3.0', reference: '1.3.2-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian 3.0.\nUpgrade to gzip_1.3.2-3woody5\n');
}
if (deb_check(prefix: 'gzip', release: '3.1', reference: '1.3.5-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian 3.1.\nUpgrade to gzip_1.3.5-10\n');
}
if (deb_check(prefix: 'gzip', release: '3.1', reference: '1.3.5-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian sarge.\nUpgrade to gzip_1.3.5-10\n');
}
if (deb_check(prefix: 'gzip', release: '3.0', reference: '1.3.2-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gzip is vulnerable in Debian woody.\nUpgrade to gzip_1.3.2-3woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
