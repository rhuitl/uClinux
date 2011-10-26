# This script was automatically generated from the dsa-1180
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Luigi Auriemma discovered two security related bugs in bomberclone, a
free Bomberman clone.  The Common Vulnerabilities and Exposures
project identifies the following problems:
    The program copies remotely provided data unchecked which could
    lead to a denial of service via an application crash.
    Bomberclone uses remotely provided data as length argument which
    can lead to the disclosure of private information.
For the stable distribution (sarge) these problems have been fixed in
version 0.11.5-1sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 0.11.7-0.1.
We recommend that you upgrade your bomberclone package.


Solution : http://www.debian.org/security/2006/dsa-1180
Risk factor : High';

if (description) {
 script_id(22722);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1180");
 script_cve_id("CVE-2006-4005", "CVE-2006-4006");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1180] DSA-1180-1 bomberclone");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1180-1 bomberclone");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bomberclone', release: '', reference: '0.11.7-0.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bomberclone is vulnerable in Debian .\nUpgrade to bomberclone_0.11.7-0.1\n');
}
if (deb_check(prefix: 'bomberclone', release: '3.1', reference: '0.11.5-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bomberclone is vulnerable in Debian 3.1.\nUpgrade to bomberclone_0.11.5-1sarge2\n');
}
if (deb_check(prefix: 'bomberclone-data', release: '3.1', reference: '0.11.5-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bomberclone-data is vulnerable in Debian 3.1.\nUpgrade to bomberclone-data_0.11.5-1sarge2\n');
}
if (deb_check(prefix: 'bomberclone', release: '3.1', reference: '0.11.5-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bomberclone is vulnerable in Debian sarge.\nUpgrade to bomberclone_0.11.5-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
