# This script was automatically generated from the dsa-973
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in otrs, the Open Ticket
Request System, that can be exploited remotely.  The Common
Vulnerabilities and Exposures Project identifies the following
problems:
    Multiple SQL injection vulnerabilities allow remote attackers to
    execute arbitrary SQL commands and bypass authentication.
    Multiple cross-site scripting vulnerabilities allow remote
    authenticated users to inject arbitrary web script or HTML.
    Internally attached text/html mails are rendered as HTML when the
    queue moderator attempts to download the attachment, which allows
    remote attackers to execute arbitrary web script or HTML.
The old stable distribution (woody) does not contain OTRS packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.2p01-6.
For the unstable distribution (sid) these problems have been fixed in
version 2.0.4p01-1.
We recommend that you upgrade your otrs package.


Solution : http://www.debian.org/security/2006/dsa-973
Risk factor : High';

if (description) {
 script_id(22839);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "973");
 script_cve_id("CVE-2005-3893", "CVE-2005-3894", "CVE-2005-3895");
 script_bugtraq_id(15537);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA973] DSA-973-1 otrs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-973-1 otrs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'otrs', release: '', reference: '2.0.4p01-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package otrs is vulnerable in Debian .\nUpgrade to otrs_2.0.4p01-1\n');
}
if (deb_check(prefix: 'otrs', release: '3.1', reference: '1.3.2p01-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package otrs is vulnerable in Debian 3.1.\nUpgrade to otrs_1.3.2p01-6\n');
}
if (deb_check(prefix: 'otrs-doc-de', release: '3.1', reference: '1.3.2p01-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package otrs-doc-de is vulnerable in Debian 3.1.\nUpgrade to otrs-doc-de_1.3.2p01-6\n');
}
if (deb_check(prefix: 'otrs-doc-en', release: '3.1', reference: '1.3.2p01-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package otrs-doc-en is vulnerable in Debian 3.1.\nUpgrade to otrs-doc-en_1.3.2p01-6\n');
}
if (deb_check(prefix: 'otrs', release: '3.1', reference: '1.3.2p01-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package otrs is vulnerable in Debian sarge.\nUpgrade to otrs_1.3.2p01-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
