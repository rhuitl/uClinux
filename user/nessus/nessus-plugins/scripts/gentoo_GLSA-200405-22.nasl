# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14508);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200405-22");
 script_cve_id("CVE-2003-0993", "CVE-2003-0020", "CVE-2003-0987", "CVE-2004-0174");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-22
(Apache 1.3: Multiple vulnerabilities)


    On 64-bit big-endian platforms, mod_access does not properly parse
    Allow/Deny rules using IP addresses without a netmask which could result in
    failure to match certain IP addresses.
    Terminal escape sequences are not filtered from error logs. This could be
    used by an attacker to insert escape sequences into a terminal emulater
    vulnerable to escape sequences.
    mod_digest does not properly verify the nonce of a client response by using
    a AuthNonce secret. This could permit an attacker to replay the response of
    another website. This does not affect mod_auth_digest.
    On certain platforms there is a starvation issue where listening sockets
    fails to handle short-lived connection on a rarely-accessed listening
    socket. This causes the child to hold the accept mutex and block out new
    connections until another connection arrives on the same rarely-accessed
    listening socket thus leading to a denial of service.
  
Impact

    These vulnerabilities could lead to attackers bypassing intended access
    restrictions, denial of service, and possibly execution of arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0993
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0020
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0987
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0174


Solution: 
    All users should upgrade to the latest stable version of Apache 1.3.
    # emerge sync
    # emerge -pv ">=net-www/apache-1.3.31"
    # emerge ">=net-www/apache-1.3.31"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-22] Apache 1.3: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 1.3: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/apache", unaffected: make_list("ge 1.3.31"), vulnerable: make_list("lt 1.3.31")
)) { security_warning(0); exit(0); }
