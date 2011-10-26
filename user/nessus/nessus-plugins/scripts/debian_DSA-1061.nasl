# This script was automatically generated from the dsa-1061
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It has been discovered that popfile, a bayesian mail classifier, can
be forced into a crash through malformed character sets within email
messages, which allows denial of service.
The old stable distribution (woody) does not contain popfile packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.22.2-2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.22.4-1.
We recommend that you upgrade your popfile package.


Solution : http://www.debian.org/security/2006/dsa-1061
Risk factor : High';

if (description) {
 script_id(22603);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1061");
 script_cve_id("CVE-2006-0876");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1061] DSA-1061-1 popfile");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1061-1 popfile");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'popfile', release: '', reference: '0.22.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package popfile is vulnerable in Debian .\nUpgrade to popfile_0.22.4-1\n');
}
if (deb_check(prefix: 'popfile', release: '3.1', reference: '0.22.2-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package popfile is vulnerable in Debian 3.1.\nUpgrade to popfile_0.22.2-2sarge1\n');
}
if (deb_check(prefix: 'popfile', release: '3.1', reference: '0.22.2-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package popfile is vulnerable in Debian sarge.\nUpgrade to popfile_0.22.2-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
