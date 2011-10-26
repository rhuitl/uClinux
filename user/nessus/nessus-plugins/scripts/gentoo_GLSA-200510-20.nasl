# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20102);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200510-20");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-20
(Zope: File inclusion through RestructuredText)


    Zope honors file inclusion directives in RestructuredText objects
    by default.
  
Impact

    An attacker could exploit the vulnerability by sending malicious
    input that would be interpreted in a RestructuredText Zope object,
    potentially resulting in the execution of arbitrary Zope code with the
    rights of the Zope server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.zope.org/Products/Zope/Hotfix_2005-10-09/security_alert


Solution: 
    All Zope users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose net-zope/zope
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-20] Zope: File inclusion through RestructuredText");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Zope: File inclusion through RestructuredText');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-zope/zope", unaffected: make_list("ge 2.7.8"), vulnerable: make_list("lt 2.7.8", "eq 2.8.0", "eq 2.8.1")
)) { security_warning(0); exit(0); }
