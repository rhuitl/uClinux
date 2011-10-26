# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19573);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200508-20");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-20
(phpGroupWare: Multiple vulnerabilities)


    phpGroupWare improperly validates the "mid" parameter retrieved
    via a forum post. The current version of phpGroupWare also adds several
    safeguards to prevent XSS issues, and disables the use of a potentially
    vulnerable XML-RPC library.
  
Impact

    A remote attacker may leverage the XML-RPC vulnerability to
    execute arbitrary PHP script code. He could also create a specially
    crafted request that will reveal private posts.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-2498
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-2600
    http://secunia.com/advisories/16414


Solution: 
    All phpGroupWare users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpgroupware-0.9.16.008"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-20] phpGroupWare: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpGroupWare: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpgroupware", unaffected: make_list("ge 0.9.16.008"), vulnerable: make_list("lt 0.9.16.008")
)) { security_hole(0); exit(0); }
