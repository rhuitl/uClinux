# This script was automatically generated from the dsa-733
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Justin Rye discovered that crip, a terminal-based ripper, encoder and
tagger tool, utilises temporary files in an insecure fashion in its
helper scripts.
The old stable distribution (woody) does not provide the crip package.
For the stable distribution (sarge) this problem has been fixed in
version 3.5-1sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 3.5-1sarge2.
We recommend that you upgrade your crip package.


Solution : http://www.debian.org/security/2005/dsa-733
Risk factor : High';

if (description) {
 script_id(18595);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "733");
 script_cve_id("CVE-2005-0393");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA733] DSA-733-1 crip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-733-1 crip");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'crip', release: '', reference: '3.5-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package crip is vulnerable in Debian .\nUpgrade to crip_3.5-1sarge2\n');
}
if (deb_check(prefix: 'crip', release: '3.1', reference: '3.5-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package crip is vulnerable in Debian 3.1.\nUpgrade to crip_3.5-1sarge2\n');
}
if (deb_check(prefix: 'crip', release: '3.1', reference: '3.5-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package crip is vulnerable in Debian sarge.\nUpgrade to crip_3.5-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
