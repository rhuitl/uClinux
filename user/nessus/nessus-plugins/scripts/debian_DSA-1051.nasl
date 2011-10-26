# This script was automatically generated from the dsa-1051
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in Mozilla
Thunderbird.  The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:
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
    Georgi Guninski reported two variants of using scripts in an XBL
    control to gain chrome privileges when the page is viewed under
    "Print Preview".  [MFSA-2006-25]
    "shutdown" discovered that the crypto.generateCRMFRequest method
    can be used to run arbitrary code with the privilege of the user
    running the browser, which could enable an attacker to install
    malware.  [MFSA-2006-24]
    Claus Jørgensen reported that a text input box can be pr
[...]

Solution : http://www.debian.org/security/2006/dsa-1051
Risk factor : High';

if (description) {
 script_id(22593);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1051");
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
 script_name(english: "[DSA1051] DSA-1051-1 mozilla-thunderbird");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1051-1 mozilla-thunderbird");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mozilla-thunderbird', release: '', reference: '1.5.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird is vulnerable in Debian .\nUpgrade to mozilla-thunderbird_1.5.0\n');
}
if (deb_check(prefix: 'mozilla-thunderbird', release: '3.1', reference: '1.0.2-2.sarge1.0.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird_1.0.2-2.sarge1.0.8\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-dev', release: '3.1', reference: '1.0.2-2.sarge1.0.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-dev is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-dev_1.0.2-2.sarge1.0.8\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-inspector', release: '3.1', reference: '1.0.2-2.sarge1.0.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-inspector is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-inspector_1.0.2-2.sarge1.0.8\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-offline', release: '3.1', reference: '1.0.2-2.sarge1.0.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-offline is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-offline_1.0.2-2.sarge1.0.8\n');
}
if (deb_check(prefix: 'mozilla-thunderbird-typeaheadfind', release: '3.1', reference: '1.0.2-2.sarge1.0.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird-typeaheadfind is vulnerable in Debian 3.1.\nUpgrade to mozilla-thunderbird-typeaheadfind_1.0.2-2.sarge1.0.8\n');
}
if (deb_check(prefix: 'mozilla-thunderbird', release: '3.1', reference: '1.0.2-2.sarge1.0.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-thunderbird is vulnerable in Debian sarge.\nUpgrade to mozilla-thunderbird_1.0.2-2.sarge1.0.8\n');
}
if (w) { security_hole(port: 0, data: desc); }
