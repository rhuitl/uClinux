# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18232);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200505-06");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-06
(TCPDump: Decoding routines Denial of Service vulnerability)


    TCPDump improperly handles and decodes ISIS (CVE-2005-1278), BGP
    (CVE-2005-1267, CVE-2005-1279), LDP (CVE-2005-1279) and RSVP
    (CVE-2005-1280) packets. TCPDump might loop endlessly after receiving
    malformed packets.
  
Impact

    A malicious remote attacker can exploit the decoding issues for a
    Denial of Service attack by sending specially crafted packets, possibly
    causing TCPDump to loop endlessly.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1267
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1278
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1279
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2005-1280


Solution: 
    All TCPDump users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/tcpdump-3.8.3-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-06] TCPDump: Decoding routines Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'TCPDump: Decoding routines Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/tcpdump", unaffected: make_list("ge 3.8.3-r3"), vulnerable: make_list("lt 3.8.3-r3")
)) { security_warning(0); exit(0); }
