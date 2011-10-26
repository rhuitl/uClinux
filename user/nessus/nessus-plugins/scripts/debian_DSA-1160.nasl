# This script was automatically generated from the dsa-1160
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The latest security updates of Mozilla introduced a regression that
led to a disfunctional attachment panel which warrants a correction to
fix this issue. For reference please find below the original advisory
text:
Several security related problems have been discovered in Mozilla and
derived products.  The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:
    Mozilla team members discovered several crashes during testing of
    the browser engine showing evidence of memory corruption which may
    also lead to the execution of arbitrary code.  The last bit of
    this problem will be corrected with the next update.  You can
    prevent any trouble by disabling Javascript.  [MFSA-2006-32]
    The Javascript engine might allow remote attackers to execute
    arbitrary code.  [MFSA-2006-50]
    Multiple integer overflows in the Javascript engine might allow
    remote attackers to execute arbitrary code.  [MFSA-2006-50]
    Specially crafted Javascript allows remote attackers to execute
    arbitrary code.  [MFSA-2006-51]
    Remote Proxy AutoConfig (PAC) servers could execute code with elevated
    privileges via a specially crafted PAC script.  [MFSA-2006-52]
    Scripts with the UniversalBrowserRead privilege could gain
    UniversalXPConnect privileges and possibly execute code or obtain
    sensitive data.  [MFSA-2006-53]
    A cross-site scripting vulnerability allows remote attackers to
    inject arbitrary web script or HTML.  [MFSA-2006-54]
For the stable distribution (sarge) these problems have been fixed in
version 1.7.8-1sarge7.2.2.
For the unstable distribution (sid) these problems won\'t be fixed
since its end of lifetime has been reached and the package will soon
be removed.
We recommend that you upgrade your mozilla package.


Solution : http://www.debian.org/security/2006/dsa-1160
Risk factor : High';

if (description) {
 script_id(22702);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1160");
 script_cve_id("CVE-2006-2779", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810");
 script_bugtraq_id(18228, 19181);
 script_xref(name: "CERT", value: "466673");
 script_xref(name: "CERT", value: "655892");
 script_xref(name: "CERT", value: "687396");
 script_xref(name: "CERT", value: "876420");
 script_xref(name: "CERT", value: "911004");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1160] DSA-1160-2 mozilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1160-2 mozilla");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libnspr-dev', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnspr-dev is vulnerable in Debian 3.1.\nUpgrade to libnspr-dev_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'libnspr4', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnspr4 is vulnerable in Debian 3.1.\nUpgrade to libnspr4_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'libnss-dev', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss-dev is vulnerable in Debian 3.1.\nUpgrade to libnss-dev_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'libnss3', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss3 is vulnerable in Debian 3.1.\nUpgrade to libnss3_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian 3.1.\nUpgrade to mozilla_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'mozilla-browser', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-browser is vulnerable in Debian 3.1.\nUpgrade to mozilla-browser_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'mozilla-calendar', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-calendar is vulnerable in Debian 3.1.\nUpgrade to mozilla-calendar_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'mozilla-chatzilla', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-chatzilla is vulnerable in Debian 3.1.\nUpgrade to mozilla-chatzilla_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'mozilla-dev', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-dev is vulnerable in Debian 3.1.\nUpgrade to mozilla-dev_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'mozilla-dom-inspector', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-dom-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-dom-inspector_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'mozilla-js-debugger', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-js-debugger is vulnerable in Debian 3.1.\nUpgrade to mozilla-js-debugger_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'mozilla-mailnews', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-mailnews is vulnerable in Debian 3.1.\nUpgrade to mozilla-mailnews_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'mozilla-psm', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-psm is vulnerable in Debian 3.1.\nUpgrade to mozilla-psm_1.7.8-1sarge7.2.2\n');
}
if (deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge7.2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian sarge.\nUpgrade to mozilla_1.7.8-1sarge7.2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
