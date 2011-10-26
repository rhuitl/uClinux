# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200604-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21198);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200604-05");
 script_cve_id("CVE-2006-1618");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200604-05
(Doomsday: Format string vulnerability)


    Luigi Auriemma discovered that Doomsday incorrectly implements
    formatted printing.
  
Impact

    A remote attacker could exploit these vulnerabilities to execute
    arbitrary code with the rights of the user running the Doomsday server
    or client by sending specially crafted strings.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1618
    http://aluigi.altervista.org/adv/doomsdayfs-adv.txt


Solution: 
    Doomsday has been masked in Portage pending the resolution of
    these issues. All Doomsday users are advised to uninstall the package
    until further notice.
    # emerge --ask --verbose --unmerge games-fps/doomsday
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200604-05] Doomsday: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Doomsday: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "games-fps/doomsday", unaffected: make_list(), vulnerable: make_list("le 1.8.6-r1")
)) { security_hole(0); exit(0); }
