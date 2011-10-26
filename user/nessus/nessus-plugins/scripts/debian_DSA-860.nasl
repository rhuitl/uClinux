# This script was automatically generated from the dsa-860
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


Solution : http://www.debian.org/security/2005/dsa-860
Risk factor : High';

if (description) {
 script_id(19968);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "860");
 script_cve_id("CVE-2005-2337");
 script_xref(name: "CERT", value: "160012");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA860] DSA-860-1 ruby");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-860-1 ruby");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'irb', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package irb is vulnerable in Debian 3.0.\nUpgrade to irb_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'libcurses-ruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcurses-ruby is vulnerable in Debian 3.0.\nUpgrade to libcurses-ruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'libdbm-ruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdbm-ruby is vulnerable in Debian 3.0.\nUpgrade to libdbm-ruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'libgdbm-ruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdbm-ruby is vulnerable in Debian 3.0.\nUpgrade to libgdbm-ruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'libnkf-ruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnkf-ruby is vulnerable in Debian 3.0.\nUpgrade to libnkf-ruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'libpty-ruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpty-ruby is vulnerable in Debian 3.0.\nUpgrade to libpty-ruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'libreadline-ruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libreadline-ruby is vulnerable in Debian 3.0.\nUpgrade to libreadline-ruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'libruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libruby is vulnerable in Debian 3.0.\nUpgrade to libruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'libsdbm-ruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsdbm-ruby is vulnerable in Debian 3.0.\nUpgrade to libsdbm-ruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'libsyslog-ruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsyslog-ruby is vulnerable in Debian 3.0.\nUpgrade to libsyslog-ruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'libtcltk-ruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtcltk-ruby is vulnerable in Debian 3.0.\nUpgrade to libtcltk-ruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'libtk-ruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtk-ruby is vulnerable in Debian 3.0.\nUpgrade to libtk-ruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'ruby', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby is vulnerable in Debian 3.0.\nUpgrade to ruby_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'ruby-dev', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby-dev is vulnerable in Debian 3.0.\nUpgrade to ruby-dev_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'ruby-elisp', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby-elisp is vulnerable in Debian 3.0.\nUpgrade to ruby-elisp_1.6.7-3woody5\n');
}
if (deb_check(prefix: 'ruby-examples', release: '3.0', reference: '1.6.7-3woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby-examples is vulnerable in Debian 3.0.\nUpgrade to ruby-examples_1.6.7-3woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
