# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14666);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0027");
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200409-09");
 script_cve_id("CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644", "CVE-2004-0772");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-09
(MIT krb5: Multiple vulnerabilities)


    The implementation of the Key Distribution Center (KDC) and the MIT krb5
    library contain double-free vulnerabilities, making client programs as well
    as application servers vulnerable.
    The ASN.1 decoder library is vulnerable to a denial of service attack,
    including the KDC.
  
Impact

    The double-free vulnerabilities could allow an attacker to execute
    arbitrary code on a KDC host and hosts running krb524d or vulnerable
    services. In the case of a KDC host, this can lead to a compromise of the
    entire Kerberos realm. Furthermore, an attacker impersonating a legitimate
    KDC or application server can potentially execute arbitrary code on
    authenticating clients.
    An attacker can cause a denial of service for a KDC or application server
    and clients, the latter if impersonating a legitimate KDC or application
    server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2004-002-dblfree.txt
    http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2004-003-asn1.txt
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0642
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0643
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0644
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0772


Solution: 
    All mit-krb5 users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=app-crypt/mit-krb5-1.3.4"
    # emerge ">=app-crypt/mit-krb5-1.3.4"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-09] MIT krb5: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIT krb5: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.3.4"), vulnerable: make_list("lt 1.3.4")
)) { security_hole(0); exit(0); }
