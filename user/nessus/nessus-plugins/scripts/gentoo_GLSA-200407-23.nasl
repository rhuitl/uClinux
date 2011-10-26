# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14556);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200407-23");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-23
(SoX: Multiple buffer overflows)


    Ulf Harnhammar discovered two buffer overflows in the sox and play commands
    when handling WAV files with specially crafted header fields.
  
Impact

    By enticing a user to play or convert a specially crafted WAV file an
    attacker could execute arbitrary code with the permissions of the user
    running SoX.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of SoX.
  
References:
    http://archives.neohapsis.com/archives/fulldisclosure/2004-07/1141.html


Solution: 
    All SoX users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-sound/sox-12.17.4-r2"
    # emerge ">=media-sound/sox-12.17.4-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-23] SoX: Multiple buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SoX: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-sound/sox", unaffected: make_list("ge 12.17.4-r2"), vulnerable: make_list("le 12.17.4-r1")
)) { security_warning(0); exit(0); }
