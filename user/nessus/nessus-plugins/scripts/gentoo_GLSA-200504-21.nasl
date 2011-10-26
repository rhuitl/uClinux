# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18121);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-21");
 script_cve_id("CVE-2005-0755");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-21
(RealPlayer, Helix Player: Buffer overflow vulnerability)


    Piotr Bania has discovered a buffer overflow vulnerability in
    RealPlayer and Helix Player when processing malicious RAM files.
  
Impact

    By enticing a user to play a specially crafted RAM file an
    attacker could execute arbitrary code with the permissions of the user
    running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0755
    http://service.real.com/help/faq/security/050419_player/EN/


Solution: 
    All RealPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/realplayer-10.0.4"
    All Helix Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/helixplayer-1.0.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-21] RealPlayer, Helix Player: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'RealPlayer, Helix Player: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/helixplayer", unaffected: make_list("ge 1.0.4"), vulnerable: make_list("lt 1.0.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-video/realplayer", unaffected: make_list("ge 10.0.4"), vulnerable: make_list("lt 10.0.4")
)) { security_warning(0); exit(0); }
