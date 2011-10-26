# This script was automatically generated from the dsa-1135
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Kevin Kofler discovered several stack-based buffer overflows in the
LookupTRM::lookup function in libtunepimp, a MusicBrainz tagging
library, which allows remote attackers to cause a denial of service or
execute arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 0.3.0-3sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 0.4.2-4.
We recommend that you upgrade your libtunepimp packages.


Solution : http://www.debian.org/security/2006/dsa-1135
Risk factor : High';

if (description) {
 script_id(22677);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1135");
 script_cve_id("CVE-2006-3600");
 script_bugtraq_id(18961);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1135] DSA-1135-1 libtunepimp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1135-1 libtunepimp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libtunepimp', release: '', reference: '0.4.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtunepimp is vulnerable in Debian .\nUpgrade to libtunepimp_0.4.2-4\n');
}
if (deb_check(prefix: 'libtunepimp-bin', release: '3.1', reference: '0.3.0-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtunepimp-bin is vulnerable in Debian 3.1.\nUpgrade to libtunepimp-bin_0.3.0-3sarge2\n');
}
if (deb_check(prefix: 'libtunepimp-perl', release: '3.1', reference: '0.3.0-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtunepimp-perl is vulnerable in Debian 3.1.\nUpgrade to libtunepimp-perl_0.3.0-3sarge2\n');
}
if (deb_check(prefix: 'libtunepimp2', release: '3.1', reference: '0.3.0-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtunepimp2 is vulnerable in Debian 3.1.\nUpgrade to libtunepimp2_0.3.0-3sarge2\n');
}
if (deb_check(prefix: 'libtunepimp2-dev', release: '3.1', reference: '0.3.0-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtunepimp2-dev is vulnerable in Debian 3.1.\nUpgrade to libtunepimp2-dev_0.3.0-3sarge2\n');
}
if (deb_check(prefix: 'python-tunepimp', release: '3.1', reference: '0.3.0-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-tunepimp is vulnerable in Debian 3.1.\nUpgrade to python-tunepimp_0.3.0-3sarge2\n');
}
if (deb_check(prefix: 'python2.2-tunepimp', release: '3.1', reference: '0.3.0-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-tunepimp is vulnerable in Debian 3.1.\nUpgrade to python2.2-tunepimp_0.3.0-3sarge2\n');
}
if (deb_check(prefix: 'python2.3-tunepimp', release: '3.1', reference: '0.3.0-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.3-tunepimp is vulnerable in Debian 3.1.\nUpgrade to python2.3-tunepimp_0.3.0-3sarge2\n');
}
if (deb_check(prefix: 'libtunepimp', release: '3.1', reference: '0.3.0-3sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtunepimp is vulnerable in Debian sarge.\nUpgrade to libtunepimp_0.3.0-3sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
