# This script was automatically generated from the dsa-988
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in Squirrelmail, a
commonly used webmail system.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Martijn Brinkers and Ben Maurer found a flaw in webmail.php that
    allows remote attackers to inject arbitrary web pages into the right
    frame via a URL in the right_frame parameter.
    Martijn Brinkers and Scott Hughes discovered an interpretation
    conflict in the MagicHTML filter that allows remote attackers to
    conduct cross-site scripting (XSS) attacks via style sheet
    specifiers with invalid (1) "/*" and "*/" comments, or (2) slashes
    inside the "url" keyword, which is processed by some web browsers
    including Internet Explorer.
    Vicente Aguilera of Internet Security Auditors, S.L. discovered a
    CRLF injection vulnerability, which allows remote attackers to
    inject arbitrary IMAP commands via newline characters in the mailbox
    parameter of the sqimap_mailbox_select command, aka "IMAP
    injection." There\'s no known way to exploit this yet.
For the old stable distribution (woody) these problems have been fixed in
version 1.2.6-5.
For the stable distribution (sarge) these problems have been fixed in
version 2:1.4.4-8.
For the unstable distribution (sid) these problems have been fixed in
version 2:1.4.6-1.
We recommend that you upgrade your squirrelmail package.


Solution : http://www.debian.org/security/2006/dsa-988
Risk factor : High';

if (description) {
 script_id(22854);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "988");
 script_cve_id("CVE-2006-0188", "CVE-2006-0195", "CVE-2006-0377");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA988] DSA-988-1 squirrelmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-988-1 squirrelmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squirrelmail', release: '', reference: '1.4.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian .\nUpgrade to squirrelmail_1.4.6-1\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian 3.0.\nUpgrade to squirrelmail_1.2.6-5\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.1', reference: '1.4.4-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian 3.1.\nUpgrade to squirrelmail_1.4.4-8\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.1', reference: '1.4.4-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian sarge.\nUpgrade to squirrelmail_1.4.4-8\n');
}
if (deb_check(prefix: 'squirrelmail', release: '3.0', reference: '1.2.6-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squirrelmail is vulnerable in Debian woody.\nUpgrade to squirrelmail_1.2.6-5\n');
}
if (w) { security_hole(port: 0, data: desc); }
