# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14710);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200409-16");
 script_cve_id("CVE-2004-0807", "CVE-2004-0808");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-16
(Samba: Denial of Service vulnerabilities)


    There is a defect in smbd\'s ASN.1 parsing. A bad packet received during the
    authentication request could throw newly-spawned smbd processes into an
    infinite loop (CVE-2004-0807). Another defect was found in nmbd\'s
    processing of mailslot packets, where a bad NetBIOS request could crash the
    nmbd process (CVE-2004-0808).
  
Impact

    A remote attacker could send specially crafted packets to trigger both
    defects. The ASN.1 parsing issue can be exploited to exhaust all available
    memory on the Samba host, potentially denying all service to that server.
    The nmbd issue can be exploited to crash the nmbd process, resulting in a
    Denial of Service condition on the Samba server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0807
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0808


Solution: 
    All Samba 3.x users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-fs/samba-3.0.7"
    # emerge ">=net-fs/samba-3.0.7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-16] Samba: Denial of Service vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.7", "lt 3.0"), vulnerable: make_list("lt 3.0.7")
)) { security_warning(0); exit(0); }
