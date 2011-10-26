# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18666);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-08
(phpGroupWare, eGroupWare: PHP script injection vulnerability)


    The XML-RPC implementations of phpGroupWare and eGroupWare fail to
    sanitize input sent to the XML-RPC server using the "POST" method.
  
Impact

    A remote attacker could exploit the XML-RPC vulnerability to
    execute arbitrary PHP script code by sending specially crafted XML data
    to the XML-RPC servers of phpGroupWare or eGroupWare.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1921


Solution: 
    All phpGroupWare users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-app/phpgroupware-0.9.16.006"
    All eGroupWare users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-app/egroupware-1.0.0.008"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-08] phpGroupWare, eGroupWare: PHP script injection vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpGroupWare, eGroupWare: PHP script injection vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpgroupware", unaffected: make_list("ge 0.9.16.006"), vulnerable: make_list("lt 0.9.16.006")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "www-apps/egroupware", unaffected: make_list("ge 1.0.0.008"), vulnerable: make_list("lt 1.0.0.008")
)) { security_hole(0); exit(0); }
