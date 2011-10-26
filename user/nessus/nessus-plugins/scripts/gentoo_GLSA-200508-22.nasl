# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19575);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200508-22");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-22
(pam_ldap: Authentication bypass vulnerability)


    When a pam_ldap client attempts to authenticate against an LDAP
    server that omits the optional error value from the
    PasswordPolicyResponseValue, the authentication attempt will always
    succeed.
  
Impact

    A remote attacker may exploit this vulnerability to bypass the
    LDAP authentication mechanism, gaining access to the system possibly
    with elevated privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2641
    http://www.kb.cert.org/vuls/id/778916


Solution: 
    All pam_ldap users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-auth/pam_ldap-180"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-22] pam_ldap: Authentication bypass vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'pam_ldap: Authentication bypass vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-auth/pam_ldap", unaffected: make_list("ge 180"), vulnerable: make_list("lt 180")
)) { security_warning(0); exit(0); }
