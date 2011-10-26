# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16446);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-09");
 script_cve_id("CVE-2005-0089");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-09
(Python: Arbitrary code execution through SimpleXMLRPCServer)


    Graham Dumpleton discovered that XML-RPC servers making use of the
    SimpleXMLRPCServer library that use the register_instance() method to
    register an object without a _dispatch() method are vulnerable to a
    flaw allowing to read or modify globals of the associated module.
  
Impact

    A remote attacker may be able to exploit the flaw in such XML-RPC
    servers to execute arbitrary code on the server host with the rights of
    the XML-RPC server.
  
Workaround

    Python users that don\'t make use of any SimpleXMLRPCServer-based
    XML-RPC servers, or making use of servers using only the
    register_function() method are not affected.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0089
    http://www.python.org/security/PSF-2005-001/


Solution: 
    All Python users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/python
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-09] Python: Arbitrary code execution through SimpleXMLRPCServer");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Python: Arbitrary code execution through SimpleXMLRPCServer');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/python", unaffected: make_list("ge 2.3.4-r1", "rge 2.3.3-r2", "rge 2.2.3-r6"), vulnerable: make_list("le 2.3.4")
)) { security_hole(0); exit(0); }
