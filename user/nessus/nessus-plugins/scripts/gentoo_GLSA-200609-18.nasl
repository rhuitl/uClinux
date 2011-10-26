# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22469);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200609-18");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200609-18
(Opera: RSA signature forgery)


    Opera makes use of OpenSSL, which fails to correctly verify PKCS #1
    v1.5 RSA signatures signed by a key with exponent 3. Some CAs in
    Opera\'s list of trusted signers are using root certificates with
    exponent 3.
  
Impact

    An attacker could forge certificates which will appear valid and signed
    by a trusted CA.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.opera.com/support/search/supsearch.dml?index=845
    http://www.gentoo.org/security/en/glsa/glsa-200609-05.xml


Solution: 
    All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/opera-9.02"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200609-18] Opera: RSA signature forgery");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: RSA signature forgery');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 9.02"), vulnerable: make_list("lt 9.02")
)) { security_warning(0); exit(0); }
