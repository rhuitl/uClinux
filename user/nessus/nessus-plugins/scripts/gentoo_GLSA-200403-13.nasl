# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14464);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200403-13");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200403-13
(Remote buffer overflow in MPlayer)


    A vulnerability exists in the MPlayer HTTP parser which may allow an
    attacker to craft a special HTTP header ("Location:") which will
    trick MPlayer into executing arbitrary code on the user\'s computer.
  
Impact

    An attacker without privileges may exploit this vulnerability remotely,
    allowing arbitrary code to be executed in order to gain unauthorized
    access.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version MPlayer for their architecture.
  
References:
    http://www.mplayerhq.hu/homepage/design6/news.html


Solution: 
    MPlayer may be upgraded as follows:
    x86 and SPARC users should:
    # emerge sync
    # emerge -pv ">=media-video/mplayer-0.92-r1"
    # emerge ">=media-video/mplayer-0.92-r1"
    AMD64 users should:
    # emerge sync
    # emerge -pv ">=media-video/mplayer-1.0_pre2-r1"
    # emerge ">=media-video/mplayer-1.0_pre2-r1"
    PPC users should:
    # emerge sync
    # emerge -pv ">=media-video/mplayer-1.0_pre3-r2"
    # emerge ">=media-video/mplayer-1.0_pre3-r2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200403-13] Remote buffer overflow in MPlayer");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Remote buffer overflow in MPlayer');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/mplayer", arch: "ppc", unaffected: make_list("ge 1.0_pre3-r3"), vulnerable: make_list("le 1.0_pre3")
)) { security_hole(0); exit(0); }
