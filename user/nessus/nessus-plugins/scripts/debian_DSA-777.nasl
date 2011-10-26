# This script was automatically generated from the dsa-777
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in Mozilla and Mozilla Firefox
that allows remote attackers to inject arbitrary Javascript from one
page into the frameset of another site.  Thunderbird is not affected
by this and Galeon will be automatically fixed as it uses Mozilla
components.
For the stable distribution (sarge) this problem has been fixed in
version 1.7.8-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.7.10-1.
We recommend that you upgrade your Mozilla package.


Solution : http://www.debian.org/security/2005/dsa-777
Risk factor : High';

if (description) {
 script_id(19433);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "777");
 script_cve_id("CVE-2004-0718", "CVE-2005-1937");
 script_bugtraq_id(14242);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA777] DSA-777-1 mozilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-777-1 mozilla");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla', release: '', reference: '1.7.10-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian .\nUpgrade to mozilla_1.7.10-1\n');
}
if (deb_check(prefix: 'libnspr-dev', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnspr-dev is vulnerable in Debian 3.1.\nUpgrade to libnspr-dev_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'libnspr4', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnspr4 is vulnerable in Debian 3.1.\nUpgrade to libnspr4_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'libnss-dev', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss-dev is vulnerable in Debian 3.1.\nUpgrade to libnss-dev_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'libnss3', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss3 is vulnerable in Debian 3.1.\nUpgrade to libnss3_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian 3.1.\nUpgrade to mozilla_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'mozilla-browser', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-browser is vulnerable in Debian 3.1.\nUpgrade to mozilla-browser_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'mozilla-calendar', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-calendar is vulnerable in Debian 3.1.\nUpgrade to mozilla-calendar_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'mozilla-chatzilla', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-chatzilla is vulnerable in Debian 3.1.\nUpgrade to mozilla-chatzilla_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'mozilla-dev', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-dev is vulnerable in Debian 3.1.\nUpgrade to mozilla-dev_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'mozilla-dom-inspector', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-dom-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-dom-inspector_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'mozilla-js-debugger', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-js-debugger is vulnerable in Debian 3.1.\nUpgrade to mozilla-js-debugger_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'mozilla-mailnews', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-mailnews is vulnerable in Debian 3.1.\nUpgrade to mozilla-mailnews_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'mozilla-psm', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-psm is vulnerable in Debian 3.1.\nUpgrade to mozilla-psm_1.7.8-1sarge1\n');
}
if (deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian sarge.\nUpgrade to mozilla_1.7.8-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
