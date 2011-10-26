# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16441);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-04");
 script_cve_id("CVE-2005-0173", "CVE-2005-0174", "CVE-2005-0175", "CVE-2005-0211");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-04
(Squid: Multiple vulnerabilities)


    Squid contains several vulnerabilities:
    Buffer overflow when handling WCCP recvfrom()
    (CVE-2005-0211).
    Loose checking of HTTP headers (CVE-2005-0173 and
    CVE-2005-0174).
    Incorrect handling of LDAP login names with spaces
    (CVE-2005-0175).
  
Impact

    An attacker could exploit:
    the WCCP buffer overflow to cause Denial of Service.
    the HTTP header parsing vulnerabilities to inject arbitrary
    response data, potentially leading to content spoofing, web cache
    poisoning and other cross-site scripting or HTTP response splitting
    attacks.
    the LDAP issue to login with several variations of the same login
    name, leading to log poisoning.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0173
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0174
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0175
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0211


Solution: 
    All Squid users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-proxy/squid-2.5.7-r5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-04] Squid: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-proxy/squid", unaffected: make_list("ge 2.5.7-r5"), vulnerable: make_list("lt 2.5.7-r5")
)) { security_warning(0); exit(0); }
