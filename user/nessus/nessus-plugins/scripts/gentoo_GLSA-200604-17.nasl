# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200604-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21299);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200604-17");
 script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938", "CVE-2006-1939", "CVE-2006-1940");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200604-17
(Ethereal: Multiple vulnerabilities in protocol dissectors)


    Coverity discovered numerous vulnerabilities in versions of
    Ethereal prior to 0.99.0, including:
    buffer overflows in the ALCAP (CVE-2006-1934), COPS (CVE-2006-1935)
    and telnet (CVE-2006-1936) dissectors.
    buffer overflows
    in the NetXray/Windows Sniffer and Network Instruments file code
    (CVE-2006-1934).
    For further details please consult the
    references below.
  
Impact

    An attacker might be able to exploit these vulnerabilities to crash
    Ethereal or execute arbitrary code with the permissions of the user
    running Ethereal, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1932
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1933
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1934
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1935
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1936
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1937
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1938
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1939
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1940
    http://www.ethereal.com/appnotes/enpa-sa-00023.html


Solution: 
    All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.99.0"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200604-17] Ethereal: Multiple vulnerabilities in protocol dissectors");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple vulnerabilities in protocol dissectors');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.99.0"), vulnerable: make_list("lt 0.99.0")
)) { security_hole(0); exit(0); }
