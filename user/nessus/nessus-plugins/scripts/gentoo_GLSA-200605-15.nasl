# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21579);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-15");
 script_cve_id("CVE-2006-2223", "CVE-2006-2224", "CVE-2006-2276");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-15
(Quagga Routing Suite: Multiple vulnerabilities)


    Konstantin V. Gavrilenko discovered two flaws in the Routing
    Information Protocol (RIP) daemon that allow the processing of RIP v1
    packets (carrying no authentication) even when the daemon is configured
    to use MD5 authentication or, in another case, even if RIP v1 is
    completely disabled. Additionally, Fredrik Widell reported that the
    Border Gateway Protocol (BGP) daemon contains a flaw that makes it lock
    up and use all available CPU when a specific command is issued from the
    telnet interface.
  
Impact

    By sending RIP v1 response packets, an unauthenticated attacker
    can alter the routing table of a router running Quagga\'s RIP daemon and
    disclose routing information. Additionally, it is possible to lock up
    the BGP daemon from the telnet interface.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2223
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2224
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2276
    http://www.quagga.net/news2.php?y=2006&m=5&d=8#id1147115280


Solution: 
    All Quagga users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/quagga-0.98.6-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-15] Quagga Routing Suite: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Quagga Routing Suite: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/quagga", unaffected: make_list("ge 0.98.6-r1"), vulnerable: make_list("lt 0.98.6-r1")
)) { security_warning(0); exit(0); }
