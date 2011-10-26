# This script was automatically generated from the dsa-1159
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The latest security updates of Mozilla Thunderbird introduced a
regression that led to a disfunctional attachment panel which warrants
a correction to fix this issue.  For reference please find below the
original advisory text:
Several security related problems have been discovered in Mozilla and
derived products such as Mozilla Thunderbird.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
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
version 1.0.2-2.sarge1.0.8b.2.
For the unstable distribution (sid) these problems have been fixed in
version 1.5.0.5-1.
We recommend that you upgrade your mozilla-thunderbird package.


Solution : http://www.debian.org/security/2006/dsa-1159
Risk factor : High';

if (description) {
 script_id(22701);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1159");
 script_cve_id("CVE-2006-2779", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3810");
 script_bugtraq_id(18228, 19181);
 script_xref(name: "CERT", value: "466673");
 script_xref(name: "CERT", value: "655892");
 script_xref(name: "CERT", value: "687396");
 script_xref(name: "CERT", value: "876420");
 script_xref(name: "CERT", value: "911004");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1159] DSA-1159-2 mozilla-thunderbird");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1159-2 mozilla-thunderbird");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla-thunderbird', release: '', reference: '1.5.0.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird is vulnerable in Debian .\nUpgrade to mozilla-thunderbird_1.5.0.5-1\n');
}
if (deb_check(prefix: 'mozilla-thunderbird', release: '3.1', reference: '1.0.2-2.sarge1.0.8b.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird_1.0.2-2.sarge1.0.8b.2\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-dev', release: '3.1', reference: '1.0.2-2.sarge1.0.8b.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-dev is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-dev_1.0.2-2.sarge1.0.8b.2\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-inspector', release: '3.1', reference: '1.0.2-2.sarge1.0.8b.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-inspector_1.0.2-2.sarge1.0.8b.2\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-offline', release: '3.1', reference: '1.0.2-2.sarge1.0.8b.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-offline is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-offline_1.0.2-2.sarge1.0.8b.2\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-typeaheadfind', release: '3.1', reference: '1.0.2-2.sarge1.0.8b.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-typeaheadfind is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-typeaheadfind_1.0.2-2.sarge1.0.8b.2\n');
}
if (deb_check(prefix: 'mozilla-thunderbird', release: '3.1', reference: '1.0.2-2.sarge1.0.8b.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird is vulnerable in Debian sarge.\nUpgrade to mozilla-thunderbird_1.0.2-2.sarge1.0.8b.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
