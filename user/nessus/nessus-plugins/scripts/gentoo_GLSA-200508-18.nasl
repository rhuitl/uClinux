# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19538);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200508-18");
 script_cve_id("CVE-2005-2498");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-18
(PhpWiki: Arbitrary command execution through XML-RPC)


    Earlier versions of PhpWiki contain an XML-RPC library that
    improperly handles XML-RPC requests and responses with malformed nested
    tags.
  
Impact

    A remote attacker could exploit this vulnerability to inject
    arbitrary PHP script code into eval() statements by sending a specially
    crafted XML document to PhpWiki.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2498


Solution: 
    All PhpWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpwiki-1.3.10-r2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-18] PhpWiki: Arbitrary command execution through XML-RPC");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PhpWiki: Arbitrary command execution through XML-RPC');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpwiki", unaffected: make_list("ge 1.3.10-r2"), vulnerable: make_list("lt 1.3.10-r2")
)) { security_hole(0); exit(0); }
