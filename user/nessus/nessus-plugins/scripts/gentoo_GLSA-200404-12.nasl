# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14477);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200404-12");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-12
(Scorched 3D server chat box format string vulnerability)


    Scorched 3D (build 36.2 and before) does not properly check the text
    entered in the Chat box (T key). Using format string characters, you can
    generate a heap overflow. This and several other unchecked buffers have
    been corrected in the build 37 release.
  
Impact

    This vulnerability can be easily exploited to remotely crash the Scorched
    3D server, disconnecting all clients. It could also theorically be used to
    execute arbitrary code on the server with the rights of the user running
    the server.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  

Solution: 
    Scorched 3D users should upgrade to version 37 or later:
    # emerge sync
    # emerge -pv ">=games-strategy/scorched3d-37"
    # emerge ">=games-strategy/scorched3d-37"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-12] Scorched 3D server chat box format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Scorched 3D server chat box format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-strategy/scorched3d", unaffected: make_list("ge 37"), vulnerable: make_list("lt 37")
)) { security_hole(0); exit(0); }
