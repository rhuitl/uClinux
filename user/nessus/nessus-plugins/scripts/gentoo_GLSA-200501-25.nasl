# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-25.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16416);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-25");
 script_cve_id("CVE-2005-0094", "CVE-2005-0095", "CVE-2005-0096", "CVE-2005-0097", "CVE-2005-0194");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-25
(Squid: Multiple vulnerabilities)


    Squid contains a vulnerability in the gopherToHTML function
    (CVE-2005-0094) and incorrectly checks the \'number of caches\' field
    when parsing WCCP_I_SEE_YOU messages (CVE-2005-0095). Furthermore the
    NTLM code contains two errors. One is a memory leak in the
    fakeauth_auth helper (CVE-2005-0096) and the other is a NULL pointer
    dereferencing error (CVE-2005-0097). Finally Squid also contains an
    error in the ACL parsing code (CVE-2005-0194).
  
Impact

    With the WCCP issue an attacker could cause denial of service by
    sending a specially crafted UDP packet. With the Gopher issue an
    attacker might be able to execute arbitrary code by enticing a user to
    connect to a malicious Gopher server. The NTLM issues could lead to
    denial of service by memory consumption or by crashing Squid. The ACL
    issue could lead to ACL bypass.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://secunia.com/advisories/13825/
    http://secunia.com/advisories/13789/
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0094
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0095
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0096
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0097
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0194


Solution: 
    All Squid users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-proxy/squid-2.5.7-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-25] Squid: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-proxy/squid", unaffected: make_list("ge 2.5.7-r2"), vulnerable: make_list("lt 2.5.7-r2")
)) { security_warning(0); exit(0); }
