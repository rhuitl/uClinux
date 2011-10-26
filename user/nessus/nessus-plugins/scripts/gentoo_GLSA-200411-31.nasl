# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-31.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15818);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-31");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-31
(ProZilla: Multiple vulnerabilities)


    ProZilla contains several exploitable buffer overflows in the code
    handling the network protocols.
  
Impact

    A remote attacker could setup a malicious server and entice a user to
    retrieve files from that server using ProZilla. This could lead to the
    execution of arbitrary code with the rights of the user running
    ProZilla.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    Currently, there is no released version of ProZilla that contains a fix
    for these issues. The original author did not respond to our queries,
    the code contains several other problems and more secure alternatives
    exist. Therefore, the ProZilla package has been hard-masked prior to
    complete removal from Portage, and current users are advised to unmerge
    the package.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-31] ProZilla: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ProZilla: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/prozilla", unaffected: make_list(), vulnerable: make_list("le 1.3.7.3")
)) { security_warning(0); exit(0); }
