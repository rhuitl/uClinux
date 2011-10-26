# This script was automatically generated from the dsa-622
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña from the Debian Security Audit Project
has discovered multiple insecure uses
of temporary files that could lead to overwriting arbitrary files via
a symlink attack.
For the stable distribution (woody) these problems have been fixed in
version 21.8-3.
The unstable distribution (sid) does not contain this package.
We recommend that you upgrade your htmlheadline package.


Solution : http://www.debian.org/security/2005/dsa-622
Risk factor : High';

if (description) {
 script_id(16087);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "622");
 script_cve_id("CVE-2004-1181");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA622] DSA-622-1 htmlheadline");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-622-1 htmlheadline");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'htmlheadline', release: '3.0', reference: '21.8-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htmlheadline is vulnerable in Debian 3.0.\nUpgrade to htmlheadline_21.8-3\n');
}
if (deb_check(prefix: 'htmlheadline', release: '3.0', reference: '21.8-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package htmlheadline is vulnerable in Debian woody.\nUpgrade to htmlheadline_21.8-3\n');
}
if (w) { security_hole(port: 0, data: desc); }
