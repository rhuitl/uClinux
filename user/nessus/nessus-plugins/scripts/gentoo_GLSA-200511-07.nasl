# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20157);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-07");
 script_cve_id("CVE-2005-3393", "CVE-2005-3409");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-07
(OpenVPN: Multiple vulnerabilities)


    The OpenVPN client contains a format string bug in the handling of
    the foreign_option in options.c. Furthermore, when the OpenVPN server
    runs in TCP mode, it may dereference a NULL pointer under specific
    error conditions.
  
Impact

    A remote attacker could setup a malicious OpenVPN server and trick
    the user into connecting to it, potentially executing arbitrary code on
    the client\'s computer. A remote attacker could also exploit the NULL
    dereference issue by sending specific packets to an OpenVPN server
    running in TCP mode, resulting in a Denial of Service condition.
  
Workaround

    Do not use "pull" or "client" options in the OpenVPN client
    configuration file, and use UDP mode for the OpenVPN server.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3393
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3409
    http://openvpn.net/changelog.html


Solution: 
    All OpenVPN users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/openvpn-2.0.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-07] OpenVPN: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenVPN: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/openvpn", unaffected: make_list("ge 2.0.4"), vulnerable: make_list("lt 2.0.4")
)) { security_warning(0); exit(0); }
