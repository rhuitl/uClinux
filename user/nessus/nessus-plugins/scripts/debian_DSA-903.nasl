# This script was automatically generated from the dsa-903
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The unzip update in DSA 903 contained a regression so that symbolic
links that are resolved later in a zip archive aren\'t supported
anymore.  This update corrects this behaviour.  For completeness,
below please find the original advisory text:
Imran Ghory discovered a race condition in the permissions setting
code in unzip.  When decompressing a file in a directory an attacker
has access to, unzip could be tricked to set the file permissions to a
different file the user has permissions to.
For the old stable distribution (woody) this problem has been fixed in
version 5.50-1woody5.
For the stable distribution (sarge) this problem has been fixed in
version 5.52-1sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 5.52-6.
We recommend that you upgrade your unzip package.


Solution : http://www.debian.org/security/2005/dsa-903
Risk factor : High';

if (description) {
 script_id(22769);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "903");
 script_cve_id("CVE-2005-2475");
 script_bugtraq_id(14450);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA903] DSA-903-2 unzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-903-2 unzip");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'unzip', release: '', reference: '5.52-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian .\nUpgrade to unzip_5.52-6\n');
}
if (deb_check(prefix: 'unzip', release: '3.0', reference: '5.50-1woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian 3.0.\nUpgrade to unzip_5.50-1woody5\n');
}
if (deb_check(prefix: 'unzip', release: '3.1', reference: '5.52-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian 3.1.\nUpgrade to unzip_5.52-1sarge3\n');
}
if (deb_check(prefix: 'unzip', release: '3.1', reference: '5.52-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian sarge.\nUpgrade to unzip_5.52-1sarge3\n');
}
if (deb_check(prefix: 'unzip', release: '3.0', reference: '5.50-1woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package unzip is vulnerable in Debian woody.\nUpgrade to unzip_5.50-1woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
