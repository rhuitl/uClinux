# This script was automatically generated from the dsa-537
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Andres Salomon noticed a problem in the CGI session management of
Ruby, an object-oriented scripting language.  CGI::Session\'s FileStore
(and presumably PStore, but not in Debian woody) implementations store
session information insecurely.  They simply create files, ignoring
permission issues.  This can lead an attacker who has also shell
access to the webserver to take over a session.
For the stable distribution (woody) this problem has been fixed in
version 1.6.7-3woody3.
For the unstable and testing distributions (sid and sarge) this
problem has been fixed in version 1.8.1+1.8.2pre1-4.
We recommend that you upgrade your libruby package.


Solution : http://www.debian.org/security/2004/dsa-537
Risk factor : High';

if (description) {
 script_id(15374);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "537");
 script_cve_id("CVE-2004-0755");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA537] DSA-537-1 ruby");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-537-1 ruby");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'irb', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package irb is vulnerable in Debian 3.0.\nUpgrade to irb_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'libcurses-ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcurses-ruby is vulnerable in Debian 3.0.\nUpgrade to libcurses-ruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'libdbm-ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdbm-ruby is vulnerable in Debian 3.0.\nUpgrade to libdbm-ruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'libgdbm-ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgdbm-ruby is vulnerable in Debian 3.0.\nUpgrade to libgdbm-ruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'libnkf-ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnkf-ruby is vulnerable in Debian 3.0.\nUpgrade to libnkf-ruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'libpty-ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpty-ruby is vulnerable in Debian 3.0.\nUpgrade to libpty-ruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'libreadline-ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libreadline-ruby is vulnerable in Debian 3.0.\nUpgrade to libreadline-ruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'libruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libruby is vulnerable in Debian 3.0.\nUpgrade to libruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'libsdbm-ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsdbm-ruby is vulnerable in Debian 3.0.\nUpgrade to libsdbm-ruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'libsyslog-ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libsyslog-ruby is vulnerable in Debian 3.0.\nUpgrade to libsyslog-ruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'libtcltk-ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtcltk-ruby is vulnerable in Debian 3.0.\nUpgrade to libtcltk-ruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'libtk-ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtk-ruby is vulnerable in Debian 3.0.\nUpgrade to libtk-ruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby is vulnerable in Debian 3.0.\nUpgrade to ruby_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'ruby-dev', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby-dev is vulnerable in Debian 3.0.\nUpgrade to ruby-dev_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'ruby-elisp', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby-elisp is vulnerable in Debian 3.0.\nUpgrade to ruby-elisp_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'ruby-examples', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby-examples is vulnerable in Debian 3.0.\nUpgrade to ruby-examples_1.6.7-3woody3\n');
}
if (deb_check(prefix: 'ruby', release: '3.1', reference: '1.8.1+1.8.2pre1-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby is vulnerable in Debian 3.1.\nUpgrade to ruby_1.8.1+1.8.2pre1-4\n');
}
if (deb_check(prefix: 'ruby', release: '3.1', reference: '1.8.1+1.8.2pre1-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby is vulnerable in Debian sarge.\nUpgrade to ruby_1.8.1+1.8.2pre1-4\n');
}
if (deb_check(prefix: 'ruby', release: '3.0', reference: '1.6.7-3woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ruby is vulnerable in Debian woody.\nUpgrade to ruby_1.6.7-3woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
