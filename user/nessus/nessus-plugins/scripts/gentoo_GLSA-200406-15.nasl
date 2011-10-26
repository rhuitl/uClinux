# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14526);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200406-15");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-15
(Usermin: Multiple vulnerabilities)


    Usermin contains two security vulnerabilities. One fails to properly
    sanitize email messages that contain malicious HTML or script code and the
    other could allow an attacker to lock out a valid user by sending an
    invalid username and password.
  
Impact

    By sending a specially crafted e-mail, an attacker can execute arbitrary
    scripts running in the context of the victim\'s browser. This can be lead to
    cookie theft and potentially to compromise of user accounts. Furthermore,
    an attacker could lock out legitimate users by sending invalid login
    information.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
References:
    http://www.securityfocus.com/bid/10521
    http://www.lac.co.jp/security/csl/intelligence/SNSadvisory_e/75_e.html


Solution: 
    Usermin users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-admin/usermin-1.080"
    # emerge ">=app-admin/usermin-1.080"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-15] Usermin: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Usermin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-admin/usermin", unaffected: make_list("ge 1.080"), vulnerable: make_list("le 1.070-r1")
)) { security_warning(0); exit(0); }
