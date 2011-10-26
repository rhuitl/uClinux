# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19533);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200508-13");
 script_cve_id("CVE-2005-2498");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-13
(PEAR XML-RPC, phpxmlrpc: New PHP script injection vulnerability)


    Stefan Esser of the Hardened-PHP Project discovered that the PEAR
    XML-RPC and phpxmlrpc libraries were improperly handling XMLRPC
    requests and responses with malformed nested tags.
  
Impact

    A remote attacker could exploit this vulnerability to inject
    arbitrary PHP script code into eval() statements by sending a specially
    crafted XML document to web applications making use of these libraries.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2498
    http://www.hardened-php.net/advisory_142005.66.html
    http://www.hardened-php.net/advisory_152005.67.html


Solution: 
    All PEAR-XML_RPC users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/PEAR-XML_RPC-1.4.0"
    All phpxmlrpc users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/phpxmlrpc-1.2-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-13] PEAR XML-RPC, phpxmlrpc: New PHP script injection vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PEAR XML-RPC, phpxmlrpc: New PHP script injection vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-php/PEAR-XML_RPC", unaffected: make_list("ge 1.4.0"), vulnerable: make_list("lt 1.4.0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/phpxmlrpc", unaffected: make_list("ge 1.2-r1"), vulnerable: make_list("lt 1.2-r1")
)) { security_hole(0); exit(0); }
