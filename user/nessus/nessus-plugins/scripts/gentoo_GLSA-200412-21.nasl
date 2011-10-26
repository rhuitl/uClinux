# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16011);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200412-21");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-21
(MPlayer: Multiple overflows)


    iDEFENSE, Ariel Berkman and the MPlayer development team found
    multiple vulnerabilities in MPlayer. These include potential heap
    overflows in Real RTSP and pnm streaming code, stack overflows in MMST
    streaming code and multiple buffer overflows in BMP demuxer and mp3lib
    code.
  
Impact

    A remote attacker could craft a malicious file or design a
    malicious streaming server. Using MPlayer to view this file or connect
    to this server could trigger an overflow and execute
    attacker-controlled code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.idefense.com/application/poi/display?id=168&type=vulnerabilities
    http://www.idefense.com/application/poi/display?id=167&type=vulnerabilities
    http://www.idefense.com/application/poi/display?id=166&type=vulnerabilities
    http://tigger.uic.edu/~jlongs2/holes/mplayer.txt


Solution: 
    All MPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/mplayer-1.0_pre5-r5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-21] MPlayer: Multiple overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MPlayer: Multiple overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/mplayer", unaffected: make_list("ge 1.0_pre5-r5"), vulnerable: make_list("le 1.0_pre5-r4")
)) { security_warning(0); exit(0); }
