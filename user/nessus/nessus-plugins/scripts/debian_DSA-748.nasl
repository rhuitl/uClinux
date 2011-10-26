# This script was automatically generated from the dsa-748
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in ruby1.8 that could allow arbitrary
command execution on a server running the ruby xmlrpc server. 
The old stable distribution (woody) did not include ruby1.8.
This problem is fixed for the current stable distribution (sarge) in
version 1.8.2-7sarge1.
This problem is fixed for the unstable distribution in version 1.8.2-8.
We recommend that you upgrade your ruby1.8 package.


Solution : http://www.debian.org/security/2005/dsa-748
Risk factor : High';

if (description) {
 script_id(18663);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "748");
 script_cve_id("CVE-2005-1992");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA748] DSA-748-1 ruby1.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-748-1 ruby1.8");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'irb1.8', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package irb1.8 is vulnerable in Debian 3.1.\nUpgrade to irb1.8_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'libdbm-ruby1.8', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdbm-ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libdbm-ruby1.8_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'libgdbm-ruby1.8', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdbm-ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libgdbm-ruby1.8_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'libopenssl-ruby1.8', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libopenssl-ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libopenssl-ruby1.8_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'libreadline-ruby1.8', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libreadline-ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libreadline-ruby1.8_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'libruby1.8', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libruby1.8_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'libruby1.8-dbg', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libruby1.8-dbg is vulnerable in Debian 3.1.\nUpgrade to libruby1.8-dbg_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'libtcltk-ruby1.8', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtcltk-ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libtcltk-ruby1.8_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'rdoc1.8', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rdoc1.8 is vulnerable in Debian 3.1.\nUpgrade to rdoc1.8_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'ri1.8', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ri1.8 is vulnerable in Debian 3.1.\nUpgrade to ri1.8_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'ruby1.8', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to ruby1.8_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'ruby1.8-dev', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby1.8-dev is vulnerable in Debian 3.1.\nUpgrade to ruby1.8-dev_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'ruby1.8-elisp', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby1.8-elisp is vulnerable in Debian 3.1.\nUpgrade to ruby1.8-elisp_1.8.2-7sarge1\n');
}
if (deb_check(prefix: 'ruby1.8-examples', release: '3.1', reference: '1.8.2-7sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby1.8-examples is vulnerable in Debian 3.1.\nUpgrade to ruby1.8-examples_1.8.2-7sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
