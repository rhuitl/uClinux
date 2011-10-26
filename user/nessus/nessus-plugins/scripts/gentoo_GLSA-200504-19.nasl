# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18102);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200504-19");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-19
(MPlayer: Two heap overflow vulnerabilities)


    Heap overflows have been found in the code handling RealMedia RTSP
    and Microsoft Media Services streams over TCP (MMST).
  
Impact

    By setting up a malicious server and enticing a user to use its
    streaming data, a remote attacker could possibly execute arbitrary code
    on the client computer with the permissions of the user running
    MPlayer.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.mplayerhq.hu/homepage/design7/news.html#vuln10
    http://www.mplayerhq.hu/homepage/design7/news.html#vuln11


Solution: 
    All MPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/mplayer-1.0_pre6-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-19] MPlayer: Two heap overflow vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MPlayer: Two heap overflow vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/mplayer", unaffected: make_list("ge 1.0_pre6-r4"), vulnerable: make_list("lt 1.0_pre6-r4")
)) { security_warning(0); exit(0); }
