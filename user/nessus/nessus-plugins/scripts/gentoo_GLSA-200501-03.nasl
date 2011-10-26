# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16394);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200501-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-03
(Mozilla, Firefox, Thunderbird: Various vulnerabilities)


    Maurycy Prodeus from isec.pl found a potentially exploitable
    buffer overflow in the handling of NNTP URLs. Furthermore, Martin (from
    ptraced.net) discovered that temporary files in recent versions of
    Mozilla-based products were sometimes stored world-readable with
    predictable names. The Mozilla Team also fixed a way of spoofing
    filenames in Firefox\'s "What should Firefox do with this file" dialog
    boxes and a potential information leak about the existence of local
    filenames.
  
Impact

    A remote attacker could craft a malicious NNTP link and entice a
    user to click it, potentially resulting in the execution of arbitrary
    code with the rights of the user running the browser. A local attacker
    could leverage the temporary file vulnerability to read the contents of
    another user\'s attachments or downloads. A remote attacker could also
    design a malicious web page that would allow to spoof filenames if the
    user uses the "Open with..." function in Firefox, or retrieve
    information on the presence of specific files in the local filesystem.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://isec.pl/vulnerabilities/isec-0020-mozilla.txt
    http://broadcast.ptraced.net/advisories/008-firefox.thunderbird.txt
    http://secunia.com/advisories/13144/


Solution: 
    All Mozilla users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/mozilla-1.7.5"
    All Mozilla binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/mozilla-bin-1.7.5"
    All Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/mozilla-firefox-1.0"
    All Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/mozilla-firefox-bin-1.0"
    All Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-0.9"
    All Thunderbird binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/mozilla-thunderbird-bin-0.9"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-03] Mozilla, Firefox, Thunderbird: Various vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla, Firefox, Thunderbird: Various vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 0.9"), vulnerable: make_list("lt 0.9")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-www/mozilla-firefox", unaffected: make_list("ge 1.0"), vulnerable: make_list("lt 1.0")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-www/mozilla", unaffected: make_list("ge 1.7.5"), vulnerable: make_list("lt 1.7.5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-www/mozilla-bin", unaffected: make_list("ge 1.7.5"), vulnerable: make_list("lt 1.7.5")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 0.9"), vulnerable: make_list("lt 0.9")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-www/mozilla-firefox-bin", unaffected: make_list("ge 1.0"), vulnerable: make_list("lt 1.0")
)) { security_warning(0); exit(0); }
