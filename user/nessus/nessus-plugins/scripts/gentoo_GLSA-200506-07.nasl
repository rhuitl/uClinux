# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18464);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200506-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-07
(Ettercap: Format string vulnerability)


    The curses_msg function of Ettercap\'s Ncurses-based user interface
    insecurely implements formatted printing.
  
Impact

    A remote attacker could craft a malicious network flow that would
    result in executing arbitrary code with the rights of the user running
    the Ettercap tool, which is often root.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1796


Solution: 
    All Ettercap users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ettercap-0.7.3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-07] Ettercap: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ettercap: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/ettercap", unaffected: make_list("ge 0.7.3"), vulnerable: make_list("lt 0.7.3")
)) { security_hole(0); exit(0); }
