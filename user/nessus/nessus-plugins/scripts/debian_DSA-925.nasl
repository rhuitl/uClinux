# This script was automatically generated from the dsa-925
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in phpBB, a fully
featured and skinnable flat webforum. The Common Vulnerabilities
and Exposures project identifies the following problems:
    Multiple interpretation errors allow remote authenticated users to
    inject arbitrary web script when remote avatars and avatar
    uploading are enabled.
    phpBB allows remote attackers to bypass protection mechanisms that
    deregister global variables that allows attackers to manipulate
    the behaviour of phpBB.
    phpBB allows remote attackers to bypass security checks when
    register_globals is enabled and the session_start function has not
    been called to handle a session.
    phpBB allows remote attackers to modify global variables and
    bypass security mechanisms.
    Multiple cross-site scripting (XSS) vulnerabilities allow remote
    attackers to inject arbitrary web scripts.
    An SQL injection vulnerability allows remote attackers to execute
    arbitrary SQL commands.
    phpBB allows remote attackers to modify regular expressions and
    execute PHP code via the signature_bbcode_uid parameter.
    Missing input sanitising of the topic type allows remote attackers
    to inject arbitrary SQL commands.
    Missing request validation permitted remote attackers to edit
    private messages of other users.
The old stable distribution (woody) does not contain phpbb2 packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.0.13+1-6sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 2.0.18-1.
We recommend that you upgrade your phpbb2 packages.


Solution : http://www.debian.org/security/2005/dsa-925
Risk factor : High';

if (description) {
 script_id(22791);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "925");
 script_cve_id("CVE-2005-3310", "CVE-2005-3415", "CVE-2005-3416", "CVE-2005-3417", "CVE-2005-3418", "CVE-2005-3419", "CVE-2005-3420");
 script_bugtraq_id(15170, 15243);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA925] DSA-925-1 phpbb2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-925-1 phpbb2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'phpbb2', release: '', reference: '2.0.18-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2 is vulnerable in Debian .\nUpgrade to phpbb2_2.0.18-1\n');
}
if (deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2 is vulnerable in Debian 3.1.\nUpgrade to phpbb2_2.0.13-6sarge2\n');
}
if (deb_check(prefix: 'phpbb2-conf-mysql', release: '3.1', reference: '2.0.13-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2-conf-mysql is vulnerable in Debian 3.1.\nUpgrade to phpbb2-conf-mysql_2.0.13-6sarge2\n');
}
if (deb_check(prefix: 'phpbb2-languages', release: '3.1', reference: '2.0.13-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2-languages is vulnerable in Debian 3.1.\nUpgrade to phpbb2-languages_2.0.13-6sarge2\n');
}
if (deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13+1-6sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2 is vulnerable in Debian sarge.\nUpgrade to phpbb2_2.0.13+1-6sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
