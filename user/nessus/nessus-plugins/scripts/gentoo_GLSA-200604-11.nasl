# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200604-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21276);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200604-11");
 script_cve_id("CVE-2006-1010");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200604-11
(Crossfire server: Denial of Service and potential arbitrary code execution)


    Luigi Auriemma discovered a vulnerability in the Crossfire game
    server, in the handling of the "oldsocketmode" option when processing
    overly large requests.
  
Impact

    An attacker can set up a malicious Crossfire client that would
    send a large request in "oldsocketmode", resulting in a Denial of
    Service on the Crossfire server and potentially in the execution of
    arbitrary code on the server with the rights of the game server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1010


Solution: 
    All Crossfire server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-server/crossfire-server-1.9.0"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200604-11] Crossfire server: Denial of Service and potential arbitrary code execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Crossfire server: Denial of Service and potential arbitrary code execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-server/crossfire-server", unaffected: make_list("ge 1.9.0"), vulnerable: make_list("lt 1.9.0")
)) { security_hole(0); exit(0); }
