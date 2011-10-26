# This script was automatically generated from the dsa-810
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in Mozilla, the web browser of
the Mozilla suite.  Since the usual praxis of backporting apparently
does not work for this package, this update is basically version
1.7.10 with the version number rolled back, and hence still named
1.7.8.  The Common Vulnerabilities and Exposures project identifies
the following problems:
    A vulnerability has been discovered in Mozilla that allows remote
    attackers to inject arbitrary Javascript from one page into the
    frameset of another site.
    The browser user interface does not properly distinguish between
    user-generated events and untrusted synthetic events, which makes
    it easier for remote attackers to perform dangerous actions that
    normally could only be performed manually by the user.
    XML scripts ran even when Javascript disabled.
    It is possible for a remote attacker to execute a callback
    function in the context of another domain (i.e. frame).
    Missing input sanitising of InstallVersion.compareTo() can cause
    the application to crash.
    Remote attackers could steal sensitive information such as cookies
    and passwords from web sites by accessing data in alien frames.
    It is possible for a Javascript dialog box to spoof a dialog box
    from a trusted site and facilitates phishing attacks.
    Remote attackers could modify certain tag properties of DOM nodes
    that could lead to the execution of arbitrary script or code.
    The Mozilla browser family does not properly clone base objects,
    which allows remote attackers to execute arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 1.7.8-1sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 1.7.10-1.
We recommend that you upgrade your Mozilla packages.


Solution : http://www.debian.org/security/2005/dsa-810
Risk factor : High';

if (description) {
 script_id(19685);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "810");
 script_cve_id("CVE-2004-0718", "CVE-2005-1937", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2263", "CVE-2005-2265", "CVE-2005-2266");
 script_bugtraq_id(14242);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA810] DSA-810-1 mozilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-810-1 mozilla");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla', release: '', reference: '1.7.10-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian .\nUpgrade to mozilla_1.7.10-1\n');
}
if (deb_check(prefix: 'libnspr-dev', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnspr-dev is vulnerable in Debian 3.1.\nUpgrade to libnspr-dev_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'libnspr4', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnspr4 is vulnerable in Debian 3.1.\nUpgrade to libnspr4_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'libnss-dev', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss-dev is vulnerable in Debian 3.1.\nUpgrade to libnss-dev_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'libnss3', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss3 is vulnerable in Debian 3.1.\nUpgrade to libnss3_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian 3.1.\nUpgrade to mozilla_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'mozilla-browser', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-browser is vulnerable in Debian 3.1.\nUpgrade to mozilla-browser_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'mozilla-calendar', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-calendar is vulnerable in Debian 3.1.\nUpgrade to mozilla-calendar_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'mozilla-chatzilla', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-chatzilla is vulnerable in Debian 3.1.\nUpgrade to mozilla-chatzilla_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'mozilla-dev', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-dev is vulnerable in Debian 3.1.\nUpgrade to mozilla-dev_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'mozilla-dom-inspector', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-dom-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-dom-inspector_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'mozilla-js-debugger', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-js-debugger is vulnerable in Debian 3.1.\nUpgrade to mozilla-js-debugger_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'mozilla-mailnews', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-mailnews is vulnerable in Debian 3.1.\nUpgrade to mozilla-mailnews_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'mozilla-psm', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-psm is vulnerable in Debian 3.1.\nUpgrade to mozilla-psm_1.7.8-1sarge2\n');
}
if (deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian sarge.\nUpgrade to mozilla_1.7.8-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
