# This script was automatically generated from the dsa-377
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
wu-ftpd, an FTP server, implements a feature whereby multiple files
can be fetched in the form of a dynamically constructed archive file,
such as a tar archive.  The names of the files to be included are
passed as command line arguments to tar, without protection against
them being interpreted as command-line options.  GNU tar supports
several command line options which can be abused, by means of this
vulnerability, to execute arbitrary programs with the privileges of
the wu-ftpd process.
Georgi Guninski pointed out that this vulnerability exists in Debian
woody.
For the stable distribution (woody) this problem has been fixed in
version 2.6.2-3woody2.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your wu-ftpd package.


Solution : http://www.debian.org/security/2003/dsa-377
Risk factor : High';

if (description) {
 script_id(15214);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "377");
 script_cve_id("CVE-1999-0997");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA377] DSA-377-1 wu-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-377-1 wu-ftpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wu-ftpd', release: '3.0', reference: '2.6.2-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian 3.0.\nUpgrade to wu-ftpd_2.6.2-3woody2\n');
}
if (deb_check(prefix: 'wu-ftpd-academ', release: '3.0', reference: '2.6.2-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd-academ is vulnerable in Debian 3.0.\nUpgrade to wu-ftpd-academ_2.6.2-3woody2\n');
}
if (deb_check(prefix: 'wu-ftpd', release: '3.0', reference: '2.6.2-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wu-ftpd is vulnerable in Debian woody.\nUpgrade to wu-ftpd_2.6.2-3woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
