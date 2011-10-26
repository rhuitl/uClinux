# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18656);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200507-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-07
(phpWebSite: Multiple vulnerabilities)


    phpWebSite fails to sanitize input sent to the XML-RPC server
    using the "POST" method. Other unspecified vulnerabilities have been
    discovered by Diabolic Crab of Hackers Center.
  
Impact

    A remote attacker could exploit the XML-RPC vulnerability to
    execute arbitrary PHP script code by sending specially crafted XML data
    to phpWebSite. The undisclosed vulnerabilities do have an unknown
    impact.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1921
    http://phpwebsite.appstate.edu/index.php?module=announce&ANN_user_op=view&ANN_id=989


Solution: 
    All phpWebSite users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-app/phpwebsite-0.10.1-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-07] phpWebSite: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpWebSite: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpwebsite", unaffected: make_list("ge 0.10.1-r1"), vulnerable: make_list("lt 0.10.1-r1")
)) { security_hole(0); exit(0); }
