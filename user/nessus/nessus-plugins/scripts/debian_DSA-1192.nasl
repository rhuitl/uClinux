# This script was automatically generated from the dsa-1192
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in Mozilla and
derived products such as Mozilla Thunderbird.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
    Fernando Ribeiro discovered that a vulnerability in the getRawDER
    function allows remote attackers to cause a denial of service
    (hang) and possibly execute arbitrary code.
    Daniel Bleichenbacher recently described an implementation error
    in RSA signature verification that cause the application to
    incorrectly trust SSL certificates.
    Priit Laes reported that a JavaScript regular expression can
    trigger a heap-based buffer overflow which allows remote attackers
    to cause a denial of service and possibly execute arbitrary code.
    A vulnerability has been discovered that allows remote attackers
    to bypass the security model and inject content into the sub-frame
    of another site.
    Georgi Guninski demonstrated that even with JavaScript disabled in
    mail (the default) an attacker can still execute JavaScript when a
    mail message is viewed, replied to, or forwarded.
    Multiple unspecified vulnerabilities in Firefox, Thunderbird and
    SeaMonkey allow remote attackers to cause a denial of service,
    corrupt memory, and possibly execute arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 1.7.8-1sarge7.3.1.
We recommend that you upgrade your Mozilla packages.


Solution : http://www.debian.org/security/2006/dsa-1192
Risk factor : High';

if (description) {
 script_id(22733);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1192");
 script_cve_id("CVE-2006-2788", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4568", "CVE-2006-4570", "CVE-2006-4571");
 script_bugtraq_id(20042);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1192] DSA-1192-1 mozilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1192-1 mozilla");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libnspr-dev', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnspr-dev is vulnerable in Debian 3.1.\nUpgrade to libnspr-dev_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'libnspr4', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnspr4 is vulnerable in Debian 3.1.\nUpgrade to libnspr4_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'libnss-dev', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss-dev is vulnerable in Debian 3.1.\nUpgrade to libnss-dev_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'libnss3', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss3 is vulnerable in Debian 3.1.\nUpgrade to libnss3_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian 3.1.\nUpgrade to mozilla_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'mozilla-browser', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-browser is vulnerable in Debian 3.1.\nUpgrade to mozilla-browser_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'mozilla-calendar', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-calendar is vulnerable in Debian 3.1.\nUpgrade to mozilla-calendar_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'mozilla-chatzilla', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-chatzilla is vulnerable in Debian 3.1.\nUpgrade to mozilla-chatzilla_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'mozilla-dev', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-dev is vulnerable in Debian 3.1.\nUpgrade to mozilla-dev_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'mozilla-dom-inspector', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-dom-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-dom-inspector_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'mozilla-js-debugger', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-js-debugger is vulnerable in Debian 3.1.\nUpgrade to mozilla-js-debugger_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'mozilla-mailnews', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-mailnews is vulnerable in Debian 3.1.\nUpgrade to mozilla-mailnews_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'mozilla-psm', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-psm is vulnerable in Debian 3.1.\nUpgrade to mozilla-psm_1.7.8-1sarge7.3.1\n');
}
if (deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge7.3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian sarge.\nUpgrade to mozilla_1.7.8-1sarge7.3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
