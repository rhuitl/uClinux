# This script was automatically generated from the dsa-1046
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
    The "run-mozilla.sh" script allows local users to create or
    overwrite arbitrary files when debugging is enabled via a symlink
    attack on temporary files.
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
    Georgi Guninski reports that forwarding mail in-line while using
    the default HTML "rich mail" editor will execute JavaScript
    embedded in the e-mail message with full privileges of the client.
    [MFSA-2006-21]
    The HTML rendering engine does not properly block external images
    from inline HTML attachments when "Block loading of remote images
    in mail messages" is enabled, which could allow remote attackers
    to obtain sensitive information.  [MFSA-2006-26]
    A vulnerability potentially allows remote attackers to cause a
    denial of service and possibly execute arbitrary code.  [MFSA-2006-20]
    A vulnerability potentially allows remote attackers to cause a
    denial of service and possibly execute arbitrary code.  [MFSA-2006-20]
    A vulnerability potentially allows remote attackers to cause a
    denial of service and possibly execute arbitrary code.  [MFSA-2006-20]
    A vulnerability potentially allows remote attackers to cause a
    denial of service and possibly execute arbitrary code.  [MFSA-2006-20]
    A vulnerability potentially allows remote attackers to cause a
    denial of service and possibly execute arbitrary code.  [MFSA-2006-20]
    Due to an interaction between XUL content windows and the history
    mechanism, some windows may to become translucent, which might
    allow remote attackers to execute arbitrary code.  [MFSA-2006-29]
    "shutdown" discovered that the security check of the function
    js_ValueToFunctionObject() can be circumvented and exploited to
    allow the installation of malware.  [MFSA-2006-28]
    Georgi Guninski reported two variants of using scripts in an XBL
    control to g
[...]

Solution : http://www.debian.org/security/2006/dsa-1046
Risk factor : High';

if (description) {
 script_id(22588);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1046");
 script_cve_id("CVE-2005-2353", "CVE-2005-4134", "CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749");
 script_bugtraq_id(15773, 16476, 16476, 16770, 16881, 17516);
 script_xref(name: "CERT", value: "179014");
 script_xref(name: "CERT", value: "252324");
 script_xref(name: "CERT", value: "329500");
 script_xref(name: "CERT", value: "350262");
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
 script_name(english: "[DSA1046] DSA-1046-1 mozilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1046-1 mozilla");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla', release: '', reference: '1.7.13-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian .\nUpgrade to mozilla_1.7.13-1\n');
}
if (deb_check(prefix: 'libnspr-dev', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnspr-dev is vulnerable in Debian 3.1.\nUpgrade to libnspr-dev_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'libnspr4', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnspr4 is vulnerable in Debian 3.1.\nUpgrade to libnspr4_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'libnss-dev', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss-dev is vulnerable in Debian 3.1.\nUpgrade to libnss-dev_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'libnss3', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnss3 is vulnerable in Debian 3.1.\nUpgrade to libnss3_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian 3.1.\nUpgrade to mozilla_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'mozilla-browser', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-browser is vulnerable in Debian 3.1.\nUpgrade to mozilla-browser_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'mozilla-calendar', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-calendar is vulnerable in Debian 3.1.\nUpgrade to mozilla-calendar_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'mozilla-chatzilla', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-chatzilla is vulnerable in Debian 3.1.\nUpgrade to mozilla-chatzilla_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'mozilla-dev', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-dev is vulnerable in Debian 3.1.\nUpgrade to mozilla-dev_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'mozilla-dom-inspector', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-dom-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-dom-inspector_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'mozilla-js-debugger', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-js-debugger is vulnerable in Debian 3.1.\nUpgrade to mozilla-js-debugger_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'mozilla-mailnews', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-mailnews is vulnerable in Debian 3.1.\nUpgrade to mozilla-mailnews_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'mozilla-psm', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-psm is vulnerable in Debian 3.1.\nUpgrade to mozilla-psm_1.7.8-1sarge5\n');
}
if (deb_check(prefix: 'mozilla', release: '3.1', reference: '1.7.8-1sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla is vulnerable in Debian sarge.\nUpgrade to mozilla_1.7.8-1sarge5\n');
}
if (w) { security_hole(port: 0, data: desc); }
