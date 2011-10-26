# This script was automatically generated from the dsa-1044
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in Mozilla
Firefox.  The Common Vulnerabilities and Exposures project identifies
the following vulnerabilities:
    Web pages with extremely long titles cause subsequent launches of
    the browser to appear to "hang" for up to a few minutes, or even
    crash if the computer has insufficient memory.  [MFSA-2006-03]
    The JavaScript interpreter does not properly dereference objects,
    which allows remote attackers to cause a denial of service or
    execute arbitrary code.  [MFSA-2006-01]
    The function allocation code allows attackers to cause a denial of
    service and possibly execute arbitrary code.  [MFSA-2006-01]
    XULDocument.persist() did not validate the attribute name,
    allowing an attacker to inject arbitrary XML and JavaScript code
    into localstore.rdf that would be read and acted upon during
    startup.  [MFSA-2006-05]
    An anonymous researcher for TippingPoint and the Zero Day
    Initiative reported that an invalid and nonsensical ordering of
    table-related tags can be exploited to execute arbitrary code.
    [MFSA-2006-27]
    A particular sequence of HTML tags can cause memory corruption
    that can be exploited to execute arbitrary code.  [MFSA-2006-18]
    Georgi Guninski reported two variants of using scripts in an XBL
    control to gain chrome privileges when the page is viewed under
    "Print Preview".  [MFSA-2006-25]
    "shutdown" discovered that the crypto.generateCRMFRequest method
    can be used to run arbitrary code with the privilege of the user
    running the browser, which could enable an attacker to install
    malware.  [MFSA-2006-24]
    Claus Jørgensen reported that a text input box can be pre-filled
    with a filename and then turned into a file-upload control,
    allowing a malicious website to steal any local file whose name
    they can guess.  [MFSA-2006-23]
    An anonymous researcher for TippingPoint and the Zero Day
    Initiative discovered an integer overflow triggered by the CSS
    letter-spacing property, which could be exploited to execute
    arbitrary code.  [MFSA-2006-22]
    "moz_bug_r_a4" discovered that some internal functions return
    prototypes instead of objects, which allows remote attackers to
    conduct cross-site scripting attacks.  [MFSA-2006-19]
    "shutdown" discovered that it is possible to bypass same-origin
    protections, allowing a malicious site to inject script into
    content from another site, which could allow the malicious page to
    steal information such as cookies or passwords from the other
    site, or perform transactions on the user\'s behalf if the user
    were already logged in.  [MFSA-2006-17]
    "moz_bug_r_a4" discovered that the compilation scope of privileged
    built-in XBL bindings is not fully protected from web content and
    can still be executed which could be used to execute arbitrary
    JavaScript, which could allow an attacker to install malware such
    as viruses and password sniffers.  [MFSA-2006-16]
    "shutdown" discovered that it is possible to ac
[...]

Solution : http://www.debian.org/security/2006/dsa-1044
Risk factor : High';

if (description) {
 script_id(22586);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1044");
 script_cve_id("CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-1727");
 script_bugtraq_id(15773, 16476, 17516);
 script_xref(name: "CERT", value: "179014");
 script_xref(name: "CERT", value: "252324");
 script_xref(name: "CERT", value: "329500");
 script_xref(name: "CERT", value: "488774");
 script_xref(name: "CERT", value: "492382");
 script_xref(name: "CERT", value: "592425");
 script_xref(name: "CERT", value: "736934");
 script_xref(name: "CERT", value: "813230");
 script_xref(name: "CERT", value: "842094");
 script_xref(name: "CERT", value: "932734");
 script_xref(name: "CERT", value: "935556");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1044] DSA-1044-1 mozilla-firefox");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1044-1 mozilla-firefox");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla-firefox', release: '', reference: '1.5.dfsg+1.5.0.2-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian .\nUpgrade to mozilla-firefox_1.5.dfsg+1.5.0.2-2\n');
}
if (deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox_1.0.4-2sarge6\n');
}
if (deb_check(prefix: 'mozilla-firefox-dom-inspector', release: '3.1', reference: '1.0.4-2sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-dom-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-dom-inspector_1.0.4-2sarge6\n');
}
if (deb_check(prefix: 'mozilla-firefox-gnome-support', release: '3.1', reference: '1.0.4-2sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox-gnome-support is vulnerable in Debian 3.1.\nUpgrade to mozilla-firefox-gnome-support_1.0.4-2sarge6\n');
}
if (deb_check(prefix: 'mozilla-firefox', release: '3.1', reference: '1.0.4-2sarge6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-firefox is vulnerable in Debian sarge.\nUpgrade to mozilla-firefox_1.0.4-2sarge6\n');
}
if (w) { security_hole(port: 0, data: desc); }
