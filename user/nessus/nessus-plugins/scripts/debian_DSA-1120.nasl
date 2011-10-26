# This script was automatically generated from the dsa-1120
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in Mozilla.
The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities:
    Eric Foley discovered that a user can be tricked to expose a local
    file to a remote attacker by displaying a local file as image in
    connection with other vulnerabilities.  [MFSA-2006-39]
    XUL attributes are associated with the wrong URL under certain
    circumstances, which might allow remote attackers to bypass
    restrictions.  [MFSA-2006-35]
    Paul Nickerson discovered that content-defined setters on an
    object prototype were getting called by privileged user interface
    code, and "moz_bug_r_a4" demonstrated that the higher privilege
    level could be passed along to the content-defined attack code.
    [MFSA-2006-37]
    A vulnerability allows remote attackers to execute arbitrary code
    and create notifications that are executed in a privileged
    context.  [MFSA-2006-43]
    Mikolaj Habryn discovered a buffer overflow in the crypto.signText function
    that allows remote attackers to execute arbitrary code via certain
    optional Certificate Authority name arguments.  [MFSA-2006-38]
    Mozilla team members discovered several crashes during testing of
    the browser engine showing evidence of memory corruption which may
    also lead to the execution of arbitrary code.  This problem has
    only partially been corrected.  [MFSA-2006-32]
    An integer overflow allows remote attackers to cause a denial of
    service and may permit the execution of arbitrary code.
    [MFSA-2006-32]
    Chuck McAuley discovered that a text input box can be pre-filled
    with a filename and then turned into a file-upload control,
    allowing a malicious website to steal any local file whose name
    they can guess.  [MFSA-2006-41, MFSA-2006-23, CVE-2006-1729]
    Masatoshi Kimura discovered that the Unicode Byte-order-Mark (BOM)
    is stripped from UTF-8 pages during the conversion to Unicode
    before the parser sees the web page, which allows remote attackers
    to conduct cross-site scripting (XSS) attacks.  [MFSA-2006-42]
    Paul Nickerson discovered that the fix for CVE-2005-0752 can be
    bypassed using nested javascript: URLs, allowing the attacker to
    execute privileged code.  [MFSA-2005-34, MFSA-2006-36]
    Paul Nickerson demonstrated that if an attacker could convince a
    user to right-click on a broken image and choose "View Image" from
    the context menu then he could get JavaScript to
    run.  [MFSA-2006-34]
    Kazuho Oku discovered that Mozilla\'s lenient handling of HTTP
    header syntax may allow remote attackers to trick the browser to
    interpret certain responses as if they were responses from two
    different sites.  [MFSA-2006-33]
    The Mozilla researcher "moz_bug_r_a4" discovered that JavaScript
    run via EvalInSandbox can escape the sandbox and gain elevated
    privilege.  [MFSA-2006-31]
For the stable distribution (sarge) these problems have been fixed in
version 1.0.4-2sarge9.
For the unstable distribution (sid) these pr
[...]

Solution : http://www.debian.org/security/2006/dsa-1120
Risk factor : High';

if (description) {
 script_id(22662);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1120");
 script_cve_id("CVE-2006-1942", "CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2777", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780");
 script_bugtraq_id(18228);
 script_xref(name: "CERT", value: "237257");
 script_xref(name: "CERT", value: "243153");
 script_xref(name: "CERT", value: "421529");
 script_xref(name: "CERT", value: "466673");
 script_xref(name: "CERT", value: "575969");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1120] DSA-1120-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1120-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla-firefox', release: '', reference: '1.5.dfsg+1.5.0.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian .\nUpgrade to mozilla-firefox_1.5.dfsg+1.5.0.4-1\n');
}
if (deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox_1.0.4-2sarge9\n');
}
if (deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-dom-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-dom-inspector_1.0.4-2sarge9\n');
}
if (deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-gnome-support is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-gnome-support_1.0.4-2sarge9\n');
}
if (deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian sarge.\nUpgrade to mozilla-firefox_1.0.4-2sarge9\n');
}
if (w) { security_hole(port: 0, data: desc); }
