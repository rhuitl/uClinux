# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-27.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16418);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-27");
 script_cve_id("CVE-2005-0006", "CVE-2005-0007", "CVE-2005-0008", "CVE-2005-0009", "CVE-2005-0010", "CVE-2005-0084");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-27
(Ethereal: Multiple vulnerabilities)


    There are multiple vulnerabilities in versions of Ethereal earlier
    than 0.10.9, including:
    The COPS dissector could go into
    an infinite loop (CVE-2005-0006).
    The DLSw dissector could
    cause an assertion, making Ethereal exit prematurely
    (CVE-2005-0007).
    The DNP dissector could cause memory
    corruption (CVE-2005-0008).
    The Gnutella dissector could cause
    an assertion, making Ethereal exit prematurely (CVE-2005-0009).
    The MMSE dissector could free statically-allocated memory
    (CVE-2005-0010).
    The X11 dissector is vulnerable to a string
    buffer overflow (CVE-2005-0084).
  
Impact

    An attacker might be able to use these vulnerabilities to crash
    Ethereal, perform DoS by CPU and disk space utilization or even execute
    arbitrary code with the permissions of the user running Ethereal, which
    could be the root user.
  
Workaround

    For a temporary workaround you can disable all affected protocol
    dissectors by selecting Analyze->Enabled Protocols... and deselecting
    them from the list. However, it is strongly recommended to upgrade to
    the latest stable version.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0006
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0007
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0008
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0009
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0010
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0084
    http://www.ethereal.com/news/item_20050120_01.html


Solution: 
    All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.10.9"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-27] Ethereal: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.9"), vulnerable: make_list("lt 0.10.9")
)) { security_hole(0); exit(0); }
