# This script was automatically generated from the dsa-639
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Andrew V. Samoilov has noticed that several bugfixes which were
applied to the source by upstream developers of mc, the midnight
commander, a file browser and manager, were not backported to the
current version of mc that Debian ships in their stable release.  The
Common Vulnerabilities and Exposures Project identifies the following
vulnerabilities:
    Multiple format string vulnerabilities
    Multiple buffer overflows
    One infinite loop vulnerability
    Denial of service via  corrupted section header
    Denial of service via null dereference
    Freeing unallocated memory
    Denial of service via use of already freed memory
    Denial of service via manipulating non-existing file handles
    Unintended program execution via insecure filename quoting
    Denial of service via a buffer underflow
For the stable distribution (woody) these problems have been fixed in
version 4.5.55-1.2woody5.
For the unstable distribution (sid) these problems should already be
fixed since they were backported from current versions.
We recommend that you upgrade your mc package.


Solution : http://www.debian.org/security/2005/dsa-639
Risk factor : High';

if (description) {
 script_id(16165);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "639");
 script_cve_id("CVE-2004-1004", "CVE-2004-1005", "CVE-2004-1009", "CVE-2004-1090", "CVE-2004-1091", "CVE-2004-1092", "CVE-2004-1093");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA639] DSA-639-1 mc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-639-1 mc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gmc', release: '3.0', reference: '4.5.55-1.2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gmc is vulnerable in Debian 3.0.\nUpgrade to gmc_4.5.55-1.2woody5\n');
}
if (deb_check(prefix: 'mc', release: '3.0', reference: '4.5.55-1.2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc is vulnerable in Debian 3.0.\nUpgrade to mc_4.5.55-1.2woody5\n');
}
if (deb_check(prefix: 'mc-common', release: '3.0', reference: '4.5.55-1.2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc-common is vulnerable in Debian 3.0.\nUpgrade to mc-common_4.5.55-1.2woody5\n');
}
if (deb_check(prefix: 'mc', release: '3.0', reference: '4.5.55-1.2woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc is vulnerable in Debian woody.\nUpgrade to mc_4.5.55-1.2woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
