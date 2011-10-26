# This script was automatically generated from the dsa-674
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Due to an incompatibility between Python 1.5 and 2.1 the last mailman
update did not run with Python 1.5 anymore.  This problem is corrected
with this update.  This advisory only updates the packages updated
with DSA 674-2.  The version in unstable is not affected since it is
not supposed to work with Python 1.5 anymore.  For completeness below
is the original advisory text:
Two security related problems have been discovered in mailman,
web-based GNU mailing list manager.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Florian Weimer discovered a cross-site scripting vulnerability in
    mailman\'s automatically generated error messages.  An attacker
    could craft an URL containing JavaScript (or other content
    embedded into HTML) which triggered a mailman error page that
    would include the malicious code verbatim.
    Several listmasters have noticed unauthorised access to archives
    of private lists and the list configuration itself, including the
    users passwords.  Administrators are advised to check the
    webserver logfiles for requests that contain "/...../" and the
    path to the archives or configuration.  This does only seem to
    affect installations running on web servers that do not strip
    slashes, such as Apache 1.3.
For the stable distribution (woody) these problems have been fixed in
version 2.0.11-1woody11.
For the unstable distribution (sid) these problems have been fixed in
version 2.1.5-6.
We recommend that you upgrade your mailman package.


Solution : http://www.debian.org/security/2005/dsa-674
Risk factor : High';

if (description) {
 script_id(16348);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "674");
 script_cve_id("CVE-2004-1177", "CVE-2005-0202");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA674] DSA-674-3 mailman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-674-3 mailman");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mailman', release: '3.0', reference: '2.0.11-1woody11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian 3.0.\nUpgrade to mailman_2.0.11-1woody11\n');
}
if (deb_check(prefix: 'mailman', release: '3.1', reference: '2.1.5-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian 3.1.\nUpgrade to mailman_2.1.5-6\n');
}
if (deb_check(prefix: 'mailman', release: '3.0', reference: '2.0.11-1woody11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailman is vulnerable in Debian woody.\nUpgrade to mailman_2.0.11-1woody11\n');
}
if (w) { security_hole(port: 0, data: desc); }
