# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14468);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0008");
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200404-03");
 script_cve_id("CVE-2003-0989");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-03
(Tcpdump Vulnerabilities in ISAKMP Parsing)


    There are two specific vulnerabilities in tcpdump, outlined in [ reference
    1 ]. In the first scenario, an attacker may send a specially-crafted ISAKMP
    Delete packet which causes tcpdump to read past the end of its buffer. In
    the second scenario, an attacker may send an ISAKMP packet with the wrong
    payload length, again causing tcpdump to read past the end of a buffer.
  
Impact

    Remote attackers could potentially cause tcpdump to crash or execute
    arbitrary code as the \'pcap\' user.
  
Workaround

    There is no known workaround at this time. All tcpdump users are encouraged
    to upgrade to the latest available version.
  
References:
    http://www.rapid7.com/advisories/R7-0017.html
    http://rhn.redhat.com/errata/RHSA-2004-008.html
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0989


Solution: 
    All tcpdump users should upgrade to the latest available version.
    ADDITIONALLY, the net-libs/libpcap package should be upgraded.
    # emerge sync
    # emerge -pv ">=net-libs/libpcap-0.8.3-r1" ">=net-analyzer/tcpdump-3.8.3-r1"
    # emerge ">=net-libs/libpcap-0.8.3-r1" ">=net-analyzer/tcpdump-3.8.3-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-03] Tcpdump Vulnerabilities in ISAKMP Parsing");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tcpdump Vulnerabilities in ISAKMP Parsing');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/tcpdump", unaffected: make_list("ge 3.8.3-r1"), vulnerable: make_list("le 3.8.1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-libs/libpcap", unaffected: make_list("ge 0.8.3-r1"), vulnerable: make_list("le 0.8.1-r1")
)) { security_hole(0); exit(0); }
