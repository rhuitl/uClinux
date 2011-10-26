# This script was automatically generated from the dsa-941
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña from the Debian Security Audit project
discovered that a script in tuxpaint, a paint program for young
children, creates a temporary file in an insecure fashion.
The old stable distribution (woody) does not contain tuxpaint packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.9.14-2sarge0.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.15b-1.
We recommend that you upgrade your tuxpaint package.


Solution : http://www.debian.org/security/2006/dsa-941
Risk factor : High';

if (description) {
 script_id(22807);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "941");
 script_cve_id("CVE-2005-3340");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA941] DSA-941-1 tuxpaint");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-941-1 tuxpaint");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tuxpaint', release: '', reference: '0.9.15b-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tuxpaint is vulnerable in Debian .\nUpgrade to tuxpaint_0.9.15b-1\n');
}
if (deb_check(prefix: 'tuxpaint', release: '3.1', reference: '0.9.14-2sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tuxpaint is vulnerable in Debian 3.1.\nUpgrade to tuxpaint_0.9.14-2sarge0\n');
}
if (deb_check(prefix: 'tuxpaint-data', release: '3.1', reference: '0.9.14-2sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tuxpaint-data is vulnerable in Debian 3.1.\nUpgrade to tuxpaint-data_0.9.14-2sarge0\n');
}
if (deb_check(prefix: 'tuxpaint', release: '3.1', reference: '0.9.14-2sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tuxpaint is vulnerable in Debian sarge.\nUpgrade to tuxpaint_0.9.14-2sarge0\n');
}
if (w) { security_hole(port: 0, data: desc); }
