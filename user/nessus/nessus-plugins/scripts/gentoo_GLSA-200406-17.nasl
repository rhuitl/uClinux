# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14528);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200406-17");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-17
(IPsec-Tools: authentication bug in racoon)


    The KAME IKE daemon racoon is used to authenticate peers during Phase 1
    when using either preshared keys, GSS-API, or RSA signatures. When using
    RSA signatures racoon validates the X.509 certificate but not the RSA
    signature.
  
Impact

    By sending a valid and trusted X.509 certificate and any private key an
    attacker could exploit this vulnerability to perform man-in-the-middle
    attacks and initiate unauthorized connections.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
References:
    http://ipsec-tools.sourceforge.net/x509sig.html


Solution: 
    All IPsec-Tools users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-firewall/ipsec-tools-0.3.3"
    # emerge ">=net-firewall/ipsec-tools-0.3.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-17] IPsec-Tools: authentication bug in racoon");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'IPsec-Tools: authentication bug in racoon');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-firewall/ipsec-tools", unaffected: make_list("ge 0.3.3"), vulnerable: make_list("lt 0.3.3")
)) { security_warning(0); exit(0); }
