# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19211);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-15");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-15
(PHP: Script injection through XML-RPC)


    James Bercegay has discovered that the XML-RPC implementation in
    PHP fails to sanitize input passed in an XML document, which is used in
    an "eval()" statement.
  
Impact

    A remote attacker could exploit the XML-RPC vulnerability to
    execute arbitrary PHP script code by sending specially crafted XML data
    to applications making use of this XML-RPC implementation.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1921


Solution: 
    All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-php/php-4.4.0"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-15] PHP: Script injection through XML-RPC");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Script injection through XML-RPC');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-php/php", unaffected: make_list("ge 4.4.0"), vulnerable: make_list("lt 4.4.0")
)) { security_hole(0); exit(0); }
