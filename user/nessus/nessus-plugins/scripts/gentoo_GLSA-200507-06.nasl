# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18647);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-06");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-06
(TikiWiki: Arbitrary command execution through XML-RPC)


    TikiWiki is vulnerable to arbitrary command execution as described
    in GLSA 200507-01.
  
Impact

    A remote attacker could exploit this vulnerability to execute
    arbitrary PHP code by sending specially crafted XML data.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://security.gentoo.org/glsa/glsa-200507-01.xml
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1921


Solution: 
    All TikiWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/tikiwiki-1.8.5-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-06] TikiWiki: Arbitrary command execution through XML-RPC");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'TikiWiki: Arbitrary command execution through XML-RPC');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/tikiwiki", unaffected: make_list("ge 1.8.5-r1"), vulnerable: make_list("lt 1.8.5-r1")
)) { security_hole(0); exit(0); }
