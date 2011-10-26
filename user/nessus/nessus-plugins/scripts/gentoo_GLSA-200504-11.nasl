# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18044);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200504-11");
 script_cve_id("CVE-2005-1108", "CVE-2005-1109");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-11
(JunkBuster: Multiple vulnerabilities)


    James Ranson reported a vulnerability when JunkBuster is configured to
    run in single-threaded mode, an attacker can modify the referrer
    setting by getting a victim to request a specially crafted URL
    (CVE-2005-1108). Tavis Ormandy of the Gentoo Linux Security Audit Team
    identified a heap corruption issue in the filtering of URLs
    (CVE-2005-1109).
  
Impact

    If JunkBuster has been configured to run in single-threaded mode, an
    attacker can disable or modify the filtering of Referrer: HTTP headers,
    potentially compromising the privacy of users. The heap corruption
    vulnerability could crash or disrupt the operation of the proxy,
    potentially executing arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1108
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1109


Solution: 
    All JunkBuster users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-proxy/junkbuster-2.0.2-r3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-11] JunkBuster: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'JunkBuster: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-proxy/junkbuster", unaffected: make_list("ge 2.0.2-r3"), vulnerable: make_list("lt 2.0.2-r3")
)) { security_hole(0); exit(0); }
