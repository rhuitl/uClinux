# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22215);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-16");
 script_cve_id("CVE-2006-3849");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-16
(Warzone 2100 Resurrection: Multiple buffer overflows)


    Luigi Auriemma discovered two buffer overflow vulnerabilities in
    Warzone 2100 Resurrection. The recvTextMessage function of the Warzone
    2100 Resurrection server and the NETrecvFile function of the client use
    insufficiently sized buffers.
  
Impact

    A remote attacker could exploit these vulnerabilities by sending
    specially crafted input to the server, or enticing a user to load a
    specially crafted file from a malicious server. This may result in the
    execution of arbitrary code with the permissions of the user running
    Warzone 2100 Resurrection.
  
Workaround

    There is no known workaround for this issue.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3849


Solution: 
    Warzone 2100 Resurrection has been masked in Portage pending the
    resolution of these issues. Warzone 2100 Resurrection players are
    advised to uninstall the package until further notice:
    # emerge --ask --unmerge "games-strategy/warzone2100"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-16] Warzone 2100 Resurrection: Multiple buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Warzone 2100 Resurrection: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-strategy/warzone2100", unaffected: make_list(), vulnerable: make_list("le 2.0.3")
)) { security_hole(0); exit(0); }
