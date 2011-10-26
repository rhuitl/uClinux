# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14725);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-17");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-17
(SUS: Local root vulnerability)


    Leon Juranic found a bug in the logging functionality of SUS that can lead
    to local privilege escalation. A format string vulnerability exists in the
    log() function due to an incorrect call to the syslog() function.
  
Impact

    An attacker with local user privileges can potentially exploit this
    vulnerability to gain root access.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://pdg.uow.edu.au/sus/CHANGES
    http://www.securityfocus.com/archive/1/375109/2004-09-11/2004-09-17/0


Solution: 
    All SUS users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-admin/sus-2.0.2-r1"
    # emerge ">=app-admin/sus-2.0.2-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-17] SUS: Local root vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SUS: Local root vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-admin/sus", unaffected: make_list("ge 2.0.2-r1"), vulnerable: make_list("lt 2.0.2-r1")
)) { security_hole(0); exit(0); }
