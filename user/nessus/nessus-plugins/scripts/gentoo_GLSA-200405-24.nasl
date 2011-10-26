# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-24.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14510);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200405-24");
 script_cve_id("CVE-2004-0433");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-24
(MPlayer, xine-lib: vulnerabilities in RTSP stream handling)


    Multiple vulnerabilities have been found and fixed in the RTSP handling
    code common to recent versions of these two packages. These vulnerabilities
    include several remotely exploitable buffer overflows.
  
Impact

    A remote attacker, posing as a RTSP stream server, can execute arbitrary
    code with the rights of the user of the software playing the stream
    (MPlayer or any player using xine-lib). Another attacker may entice a user
    to use a maliciously crafted URL or playlist to achieve the same results.
  
Workaround

    For MPlayer, there is no known workaround at this time. For xine-lib, you
    can delete the xineplug_inp_rtsp.so file.
  
References:
    http://xinehq.de/index.php/security/XSA-2004-3
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0433


Solution: 
    All users should upgrade to non-vulnerable versions of MPlayer and
    xine-lib:
    # emerge sync
    # emerge -pv ">=media-video/mplayer-1.0_pre4"
    # emerge ">=media-video/mplayer-1.0_pre4"
    # emerge -pv ">=media-libs/xine-lib-1_rc4"
    # emerge ">=media-libs/xine-lib-1_rc4"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-24] MPlayer, xine-lib: vulnerabilities in RTSP stream handling");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MPlayer, xine-lib: vulnerabilities in RTSP stream handling');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/mplayer", unaffected: make_list("ge 1.0_pre4", "le 0.92-r1"), vulnerable: make_list("lt 1.0_pre4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1_rc4", "le 0.9.13-r3"), vulnerable: make_list("lt 1_rc4")
)) { security_hole(0); exit(0); }
