# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19576);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200509-01");
 script_cve_id("CVE-2005-2718");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-01
(MPlayer: Heap overflow in ad_pcm.c)


    Sven Tantau discovered a heap overflow in the code handling the
    strf chunk of PCM audio streams.
  
Impact

    An attacker could craft a malicious video or audio file which,
    when opened using MPlayer, would end up executing arbitrary code on the
    victim\'s computer with the permissions of the user running MPlayer.
  
Workaround

    You can mitigate the issue by adding "ac=-pcm," to your MPlayer
    configuration file (note that this will prevent you from playing
    uncompressed audio).
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2718
    http://www.sven-tantau.de/public_files/mplayer/mplayer_20050824.txt


Solution: 
    All MPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/mplayer-1.0_pre7-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-01] MPlayer: Heap overflow in ad_pcm.c");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MPlayer: Heap overflow in ad_pcm.c');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/mplayer", unaffected: make_list("ge 1.0_pre7-r1"), vulnerable: make_list("lt 1.0_pre7-r1")
)) { security_warning(0); exit(0); }
