# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21001);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-03");
 script_cve_id("CVE-2005-4048", "CVE-2006-0579");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-03
(MPlayer: Multiple integer overflows)


    MPlayer makes use of the FFmpeg library, which is vulnerable to a
    heap overflow in the avcodec_default_get_buffer() function discovered
    by Simon Kilvington (see GLSA 200601-06). Furthermore, AFI Security
    Research discovered two integer overflows in ASF file format decoding,
    in the new_demux_packet() function from libmpdemux/demuxer.h and the
    demux_asf_read_packet() function from libmpdemux/demux_asf.c.
  
Impact

    An attacker could craft a malicious media file which, when opened
    using MPlayer, would lead to a heap-based buffer overflow. This could
    result in the execution of arbitrary code with the permissions of the
    user running MPlayer.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4048
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0579
    http://www.gentoo.org/security/en/glsa/glsa-200601-06.xml


Solution: 
    All MPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/mplayer-1.0.20060217"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-03] MPlayer: Multiple integer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MPlayer: Multiple integer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/mplayer", unaffected: make_list("ge 1.0.20060217"), vulnerable: make_list("lt 1.0.20060217")
)) { security_warning(0); exit(0); }
