# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20031);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200510-11");
 script_cve_id("CVE-2005-2969");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-11
(OpenSSL: SSL 2.0 protocol rollback)


    Applications setting the SSL_OP_MSIE_SSLV2_RSA_PADDING option (or
    the SSL_OP_ALL option, that implies it) can be forced by a third-party
    to fallback to the less secure SSL 2.0 protocol, even if both parties
    support the more secure SSL 3.0 or TLS 1.0 protocols.
  
Impact

    A man-in-the-middle attacker can weaken the encryption used to
    communicate between two parties, potentially revealing sensitive
    information.
  
Workaround

    If possible, disable the use of SSL 2.0 in all OpenSSL-enabled
    applications.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2969
    http://www.openssl.org/news/secadv_20051011.txt 


Solution: 
    All OpenSSL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-libs/openssl
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-11] OpenSSL: SSL 2.0 protocol rollback");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSL: SSL 2.0 protocol rollback');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-libs/openssl", unaffected: make_list("ge 0.9.8-r1", "rge 0.9.7h", "rge 0.9.7g-r1", "rge 0.9.7e-r2"), vulnerable: make_list("lt 0.9.8-r1")
)) { security_warning(0); exit(0); }
