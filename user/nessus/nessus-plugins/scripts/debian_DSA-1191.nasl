# This script was automatically generated from the dsa-1191
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
version 1.0.2-2.sarge1.0.8c.1.
For the unstable distribution (sid) these problems have been fixed in
version 1.5.0.7-1.
We recommend that you upgrade your Mozilla Thunderbird packages.


Solution : http://www.debian.org/security/2006/dsa-1191
Risk factor : High';

if (description) {
 script_id(22732);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1191");
 script_cve_id("CVE-2006-2788", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4568", "CVE-2006-4570", "CVE-2006-4571");
 script_bugtraq_id(20042);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1191] DSA-1191-1 mozilla-thunderbird");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1191-1 mozilla-thunderbird");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla-thunderbird', release: '', reference: '1.5.0.7-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird is vulnerable in Debian .\nUpgrade to mozilla-thunderbird_1.5.0.7-1\n');
}
if (deb_check(prefix: 'mozilla-thunderbird', release: '3.1', reference: '1.0.2-2.sarge1.0.8c.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird_1.0.2-2.sarge1.0.8c.1\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-dev', release: '3.1', reference: '1.0.2-2.sarge1.0.8c.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-dev is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-dev_1.0.2-2.sarge1.0.8c.1\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-inspector', release: '3.1', reference: '1.0.2-2.sarge1.0.8c.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-inspector_1.0.2-2.sarge1.0.8c.1\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-offline', release: '3.1', reference: '1.0.2-2.sarge1.0.8c.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-offline is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-offline_1.0.2-2.sarge1.0.8c.1\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-typeaheadfind', release: '3.1', reference: '1.0.2-2.sarge1.0.8c.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-typeaheadfind is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-typeaheadfind_1.0.2-2.sarge1.0.8c.1\n');
}
if (deb_check(prefix: 'mozilla-thunderbird', release: '3.1', reference: '1.0.2-2.sarge1.0.8c.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird is vulnerable in Debian sarge.\nUpgrade to mozilla-thunderbird_1.0.2-2.sarge1.0.8c.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
