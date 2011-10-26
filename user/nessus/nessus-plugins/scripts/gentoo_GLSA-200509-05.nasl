# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19670);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200509-05");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-05
(Net-SNMP: Insecure RPATH)


    James Cloos reported that Perl modules from the Net-SNMP package
    look for libraries in an untrusted location. This is due to a flaw in
    the Gentoo package, and not the Net-SNMP suite.
  
Impact

    A local attacker (member of the portage group) may be able to
    create a shared object that would be loaded by the Net-SNMP Perl
    modules, executing arbitrary code with the privileges of the user
    invoking the Perl script.
  
Workaround

    Limit group portage access to trusted users.
  

Solution: 
    All Net-SNMP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/net-snmp-5.2.1.2-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-05] Net-SNMP: Insecure RPATH");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Net-SNMP: Insecure RPATH');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/net-snmp", unaffected: make_list("ge 5.2.1.2-r1"), vulnerable: make_list("lt 5.2.1.2-r1")
)) { security_warning(0); exit(0); }
