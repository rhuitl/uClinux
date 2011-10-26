# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200610-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22914);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200610-11");
 script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200610-11
(OpenSSL: Multiple vulnerabilities)


    Tavis Ormandy and Will Drewry, both of the Google Security Team,
    discovered that the SSL_get_shared_ciphers() function contains a buffer
    overflow vulnerability, and that the SSLv2 client code contains a flaw
    leading to a crash. Additionally Dr. Stephen N. Henson found that the
    ASN.1 handler contains two Denial of Service vulnerabilities: while
    parsing an invalid ASN.1 structure and while handling certain types of
    public key.
  
Impact

    An attacker could trigger the buffer overflow vulnerability by sending
    a malicious suite of ciphers to an application using the vulnerable
    function, and thus execute arbitrary code with the rights of the user
    running the application. An attacker could also consume CPU and/or
    memory by exploiting the Denial of Service vulnerabilities. Finally a
    malicious server could crash a SSLv2 client through the SSLv2
    vulnerability.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2937
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2940
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3738
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4343


Solution: 
    All OpenSSL 0.9.8 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/openssl-0.9.8d"
    All OpenSSL 0.9.7 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/openssl-0.9.7l"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200610-11] OpenSSL: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-libs/openssl", unaffected: make_list("ge 0.9.8d", "rge 0.9.7l"), vulnerable: make_list("lt 0.9.8d")
)) { security_hole(0); exit(0); }
