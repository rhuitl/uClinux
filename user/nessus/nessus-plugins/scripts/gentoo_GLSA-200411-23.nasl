# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15724);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-23");
 script_cve_id("CVE-2004-0983");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-23
(Ruby: Denial of Service issue)


    Ruby\'s developers found and fixed an issue in the CGI module that
    can be triggered remotely and cause an infinite loop.
  
Impact

    A remote attacker could trigger the vulnerability through an
    exposed Ruby web application and cause the server to use unnecessary
    CPU resources, potentially resulting in a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0983


Solution: 
    All Ruby 1.6.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/ruby-1.6.8-r12"
    All Ruby 1.8.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/ruby-1.8.2_pre3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-23] Ruby: Denial of Service issue");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ruby: Denial of Service issue');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/ruby", unaffected: make_list("rge 1.6.8-r12", "ge 1.8.2_pre3"), vulnerable: make_list("lt 1.8.2_pre3")
)) { security_warning(0); exit(0); }
