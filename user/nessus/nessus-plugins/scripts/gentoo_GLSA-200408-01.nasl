# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14557);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-01
(MPlayer: GUI filename handling overflow)


    The MPlayer GUI code contains several buffer overflow vulnerabilities, and
    at least one in the TranslateFilename() function is exploitable.
  
Impact

    By enticing a user to play a file with a carefully crafted filename an
    attacker could execute arbitrary code with the permissions of the user
    running MPlayer.
  
Workaround

    To work around this issue, users can compile MPlayer without GUI support by
    disabling the gtk USE flag. All users are encouraged to upgrade to the
    latest available version of MPlayer.
  
References:
    http://www.securityfocus.com/bid/10615/
    http://www.open-security.org/advisories/5


Solution: 
    All MPlayer users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-video/mplayer-1.0_pre4-r7"
    # emerge ">=media-video/mplayer-1.0_pre4-r7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-01] MPlayer: GUI filename handling overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MPlayer: GUI filename handling overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-video/mplayer", unaffected: make_list("ge 1.0_pre4-r7"), vulnerable: make_list("lt 1.0_pre4-r7")
)) { security_warning(0); exit(0); }
