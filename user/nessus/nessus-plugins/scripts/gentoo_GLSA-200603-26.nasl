# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21166);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-26");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-26
(bsd-games: Local privilege escalation in tetris-bsd)


    Tavis Ormandy of the Gentoo Linux Security Audit Team discovered
    that the checkscores() function in scores.c reads in the data from the
    /var/games/tetris-bsd.scores file without validation, rendering it
    vulnerable to buffer overflows and incompatible with the system used
    for managing games on Gentoo Linux. As a result, it cannot be played
    securely on systems with multiple users. Please note that this is
    probably a Gentoo-specific issue.
  
Impact

    A local user who is a member of group "games" may be able to
    modify the tetris-bsd.scores file to trigger the execution of arbitrary
    code with the privileges of other players.
  
Workaround

    Do not add untrusted users to the "games" group.
  

Solution: 
    All bsd-games users are advised to update to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-misc/bsd-games-2.17-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-26] bsd-games: Local privilege escalation in tetris-bsd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'bsd-games: Local privilege escalation in tetris-bsd');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-misc/bsd-games", unaffected: make_list("ge 2.17-r1"), vulnerable: make_list("lt 2.17-r1")
)) { security_warning(0); exit(0); }
