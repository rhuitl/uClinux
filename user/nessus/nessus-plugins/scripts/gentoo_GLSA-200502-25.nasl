# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-25.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17144);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-25");
 script_cve_id("CVE-2005-0446");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-25
(Squid: Denial of Service through DNS responses)


    Handling of certain DNS responses trigger assertion failures.
  
Impact

    By returning a specially crafted DNS response an attacker could
    cause Squid to crash by triggering an assertion failure.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0446


Solution: 
    All Squid users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-proxy/squid-2.5.8"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-25] Squid: Denial of Service through DNS responses");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid: Denial of Service through DNS responses');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-proxy/squid", unaffected: make_list("ge 2.5.8"), vulnerable: make_list("lt 2.5.8")
)) { security_warning(0); exit(0); }
