# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18686);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0027");
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200507-11");
 script_cve_id("CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1689");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-11
(MIT Kerberos 5: Multiple vulnerabilities)


    Daniel Wachdorf discovered that MIT Kerberos 5 could corrupt the
    heap by freeing unallocated memory when receiving a special TCP request
    (CVE-2005-1174). He also discovered that the same request could lead to
    a single-byte heap overflow (CVE-2005-1175). Magnus Hagander discovered
    that krb5_recvauth() function of MIT Kerberos 5 might try to
    double-free memory (CVE-2005-1689).
  
Impact

    Although exploitation is considered difficult, a remote attacker
    could exploit the single-byte heap overflow and the double-free
    vulnerability to execute arbitrary code, which could lead to the
    compromise of the whole Kerberos realm. A remote attacker could also
    use the heap corruption to cause a Denial of Service.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1174
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1175
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1689
    http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2005-002-kdc.txt
    http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2005-003-recvauth.txt


Solution: 
    All MIT Kerberos 5 users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/mit-krb5-1.4.1-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-11] MIT Kerberos 5: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIT Kerberos 5: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.4.1-r1"), vulnerable: make_list("lt 1.4.1-r1")
)) { security_hole(0); exit(0); }
