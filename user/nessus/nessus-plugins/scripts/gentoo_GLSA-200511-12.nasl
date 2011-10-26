# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20233);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-12");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-12
(Scorched 3D: Multiple vulnerabilities)


    Luigi Auriemma discovered multiple flaws in the Scorched 3D game
    server, including a format string vulnerability and several buffer
    overflows.
  
Impact

    A remote attacker can exploit these vulnerabilities to crash a
    game server or execute arbitrary code with the rights of the game
    server user. Users not running a Scorched 3D game server are not
    affected by these flaws.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://seclists.org/lists/fulldisclosure/2005/Nov/0079.html


Solution: 
    The Scorched 3D package has been hard-masked until a new version
    correcting these flaws is released. In the meantime, current users are
    advised to unmerge the package:
    # emerge --unmerge games-strategy/scorched3d
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-12] Scorched 3D: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Scorched 3D: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-strategy/scorched3d", unaffected: make_list(), vulnerable: make_list("le 39.1")
)) { security_hole(0); exit(0); }
