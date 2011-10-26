# This script was automatically generated from the dsa-864
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Yutaka Oiwa discovered a bug in Ruby, the interpreter for the
object-oriented scripting language, that can cause illegal program
code to bypass the safe level and taint flag protections check and be
executed.  The following matrix lists the fixed versions in our
distributions:
We recommend that you upgrade your ruby packages.


Solution : http://www.debian.org/security/2005/dsa-864
Risk factor : High';

if (description) {
 script_id(20019);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "864");
 script_cve_id("CVE-2005-2337");
 script_xref(name: "CERT", value: "160012");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA864] DSA-864-1 ruby1.8");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-864-1 ruby1.8");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'irb1.8', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package irb1.8 is vulnerable in Debian 3.1.\nUpgrade to irb1.8_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'libdbm-ruby1.8', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdbm-ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libdbm-ruby1.8_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'libgdbm-ruby1.8', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdbm-ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libgdbm-ruby1.8_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'libopenssl-ruby1.8', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libopenssl-ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libopenssl-ruby1.8_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'libreadline-ruby1.8', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libreadline-ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libreadline-ruby1.8_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'libruby1.8', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libruby1.8_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'libruby1.8-dbg', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libruby1.8-dbg is vulnerable in Debian 3.1.\nUpgrade to libruby1.8-dbg_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'libtcltk-ruby1.8', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtcltk-ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to libtcltk-ruby1.8_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'rdoc1.8', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package rdoc1.8 is vulnerable in Debian 3.1.\nUpgrade to rdoc1.8_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'ri1.8', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ri1.8 is vulnerable in Debian 3.1.\nUpgrade to ri1.8_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'ruby1.8', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby1.8 is vulnerable in Debian 3.1.\nUpgrade to ruby1.8_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'ruby1.8-dev', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby1.8-dev is vulnerable in Debian 3.1.\nUpgrade to ruby1.8-dev_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'ruby1.8-elisp', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby1.8-elisp is vulnerable in Debian 3.1.\nUpgrade to ruby1.8-elisp_1.8.2-7sarge2\n');
}
if (deb_check(prefix: 'ruby1.8-examples', release: '3.1', reference: '1.8.2-7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby1.8-examples is vulnerable in Debian 3.1.\nUpgrade to ruby1.8-examples_1.8.2-7sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
