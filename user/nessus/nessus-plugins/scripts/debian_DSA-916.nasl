# This script was automatically generated from the dsa-916
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in Inkscape, a
vector-based drawing program.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Joxean Koret discovered a buffer overflow in the SVG parsing
    routines that can lead to the execution of arbitrary code.
    Javier Fernández-Sanguino Peña noticed that the ps2epsi extension
    shell script uses a hardcoded temporary file making it vulnerable
    to symlink attacks.
The old stable distribution (woody) does not contain inkscape packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.41-4.99.sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 0.42.2+0.43pre1-1.
We recommend that you upgrade your inkscape package.


Solution : http://www.debian.org/security/2005/dsa-916
Risk factor : High';

if (description) {
 script_id(22782);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "916");
 script_cve_id("CVE-2005-3737", "CVE-2005-3885");
 script_bugtraq_id(14522);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA916] DSA-916-1 inkscape");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-916-1 inkscape");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'inkscape', release: '', reference: '0.42.2+0.43pre1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package inkscape is vulnerable in Debian .\nUpgrade to inkscape_0.42.2+0.43pre1-1\n');
}
if (deb_check(prefix: 'inkscape', release: '3.1', reference: '0.41-4.99.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package inkscape is vulnerable in Debian 3.1.\nUpgrade to inkscape_0.41-4.99.sarge2\n');
}
if (deb_check(prefix: 'inkscape', release: '3.1', reference: '0.41-4.99.sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package inkscape is vulnerable in Debian sarge.\nUpgrade to inkscape_0.41-4.99.sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
