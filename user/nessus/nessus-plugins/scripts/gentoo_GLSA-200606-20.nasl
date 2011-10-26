# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21732);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-20");
 script_cve_id("CVE-2006-1515");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-20
(Typespeed: Remote execution of arbitrary code)


    Niko Tyni discovered a buffer overflow in the addnewword() function of
    Typespeed\'s network code.
  
Impact

    By sending specially crafted network packets to a machine running
    Typespeed in multiplayer mode, a remote attacker can execute arbitrary
    code with the permissions of the user running the game.
  
Workaround

    Do not run Typespeed in multiplayer mode. There is no known workaround
    at this time for multiplayer mode.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1515


Solution: 
    All Typespeed users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-misc/typespeed-0.5.0"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-20] Typespeed: Remote execution of arbitrary code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Typespeed: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-misc/typespeed", unaffected: make_list("ge 0.5.0"), vulnerable: make_list("lt 0.5.0")
)) { security_hole(0); exit(0); }
