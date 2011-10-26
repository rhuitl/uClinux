# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18229);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200505-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-03
(Ethereal: Numerous vulnerabilities)


    There are numerous vulnerabilities in versions of Ethereal prior
    to 0.10.11, including:
    The ANSI A and DHCP dissectors are
    vulnerable to format string vulnerabilities.
    The DISTCC,
    FCELS, SIP, ISIS, CMIP, CMP, CMS, CRMF, ESS, OCSP, PKIX1Explitit, PKIX
    Qualified, X.509, Q.931, MEGACO, NCP, ISUP, TCAP and Presentation
    dissectors are vulnerable to buffer overflows.
    The KINK, WSP,
    SMB Mailslot, H.245, MGCP, Q.931, RPC, GSM and SMB NETLOGON dissectors
    are vulnerable to pointer handling errors.
    The LMP, KINK,
    MGCP, RSVP, SRVLOC, EIGRP, MEGACO, DLSw, NCP and L2TP dissectors are
    vulnerable to looping problems.
    The Telnet and DHCP dissectors
    could abort.
    The TZSP, Bittorrent, SMB, MGCP and ISUP
    dissectors could cause a segmentation fault.
    The WSP, 802.3
    Slow protocols, BER, SMB Mailslot, SMB, NDPS, IAX2, RADIUS, SMB PIPE,
    MRDISC and TCAP dissectors could throw assertions.
    The DICOM,
    NDPS and ICEP dissectors are vulnerable to memory handling errors.
    The GSM MAP, AIM, Fibre Channel,SRVLOC, NDPS, LDAP and NTLMSSP
    dissectors could terminate abnormallly.
  
Impact

    An attacker might be able to use these vulnerabilities to crash
    Ethereal and execute arbitrary code with the permissions of the user
    running Ethereal, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.ethereal.com/appnotes/enpa-sa-00019.html
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1456
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1457
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1458
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1459
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1460
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1461
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1462
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1463
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1464
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1465
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1466
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1467
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1468
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1469
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1470


Solution: 
    All Ethereal users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/ethereal-0.10.11"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-03] Ethereal: Numerous vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Numerous vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.11"), vulnerable: make_list("lt 0.10.11")
)) { security_hole(0); exit(0); }
