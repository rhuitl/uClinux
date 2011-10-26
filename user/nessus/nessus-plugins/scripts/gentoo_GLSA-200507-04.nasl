# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18633);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-04");
 script_cve_id("CVE-2005-1766");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-04
(RealPlayer: Heap overflow vulnerability)


    RealPlayer is vulnerable to a heap overflow when opening RealMedia
    files which make use of RealText.
  
Impact

    By enticing a user to play a specially crafted RealMedia file an
    attacker could execute arbitrary code with the permissions of the user
    running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://service.real.com/help/faq/security/050623_player/EN/
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1766


Solution: 
    All RealPlayer users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/realplayer-10.0.5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-04] RealPlayer: Heap overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'RealPlayer: Heap overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/realplayer", unaffected: make_list("ge 10.0.5"), vulnerable: make_list("lt 10.0.5")
)) { security_warning(0); exit(0); }
