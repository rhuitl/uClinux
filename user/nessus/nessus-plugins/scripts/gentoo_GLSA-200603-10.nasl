# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21048);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-10");
 script_cve_id("CVE-2006-1100", "CVE-2006-1101", "CVE-2006-1102");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-10
(Cube: Multiple vulnerabilities)


    Luigi Auriemma reported that Cube is vulnerable to a buffer
    overflow in the sgetstr() function (CVE-2006-1100) and that the
    sgetstr() and getint() functions fail to verify the length of the
    supplied argument, possibly leading to the access of invalid memory
    regions (CVE-2006-1101). Furthermore, he discovered that a client
    crashes when asked to load specially crafted mapnames (CVE-2006-1102).
  
Impact

    A remote attacker could exploit the buffer overflow to execute
    arbitrary code with the rights of the user running cube. An attacker
    could also exploit the other vulnerabilities to crash a Cube client or
    server, resulting in a Denial of Service.
  
Workaround

    Play solo games or restrict your multiplayer games to trusted
    parties.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1100
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1101
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1102


Solution: 
    Upstream stated that there will be no fixed version of Cube, thus
    the Gentoo Security Team decided to hardmask Cube for security reasons.
    All Cube users are encouraged to uninstall Cube:
    # emerge --ask --unmerge games-fps/cube
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-10] Cube: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cube: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-fps/cube", unaffected: make_list(), vulnerable: make_list("le 20050829")
)) { security_hole(0); exit(0); }
