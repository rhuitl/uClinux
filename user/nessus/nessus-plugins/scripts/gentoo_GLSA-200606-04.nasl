# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21671);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-04");
 script_cve_id("CVE-2006-0414");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-04
(Tor: Several vulnerabilities)


    Some integer overflows exist when adding elements to the
    smartlists. Non-printable characters received from the network are
    not properly sanitised before being logged. There are additional
    unspecified bugs in the directory server and in the internal circuits.
  
Impact

    The possible buffer overflow may allow a remote attacker to
    execute arbitrary code on the server by sending large inputs.
    The other vulnerabilities can lead to a Denial of Service,
    a lack of logged information, or some information disclosure.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0414
    http://tor.eff.org/cvs/tor/ChangeLog


Solution: 
    All Tor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/tor-0.1.1.20"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-04] Tor: Several vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tor: Several vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/tor", unaffected: make_list("ge 0.1.1.20"), vulnerable: make_list("lt 0.1.1.20")
)) { security_warning(0); exit(0); }
