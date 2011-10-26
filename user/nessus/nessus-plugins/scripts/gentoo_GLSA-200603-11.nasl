# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21084);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-11");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-11
(Freeciv: Denial of Service)


    Luigi Auriemma discovered that Freeciv could be tricked into the
    allocation of enormous chunks of memory when trying to uncompress
    malformed data packages, possibly leading to an out of memory condition
    which causes Freeciv to crash or freeze.
  
Impact

    A remote attacker could exploit this issue to cause a Denial of
    Service by sending specially crafted data packages to the Freeciv game
    server.
  
Workaround

    Play solo games or restrict your multiplayer games to trusted
    parties.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0047
    http://aluigi.altervista.org/adv/freecivdos-adv.txt


Solution: 
    All Freeciv users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-strategy/freeciv-2.0.8"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-11] Freeciv: Denial of Service");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Freeciv: Denial of Service');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-strategy/freeciv", unaffected: make_list("ge 2.0.8"), vulnerable: make_list("lt 2.0.8")
)) { security_warning(0); exit(0); }
