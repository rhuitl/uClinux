# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14648);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200409-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-01
(vpopmail: Multiple vulnerabilities)


    vpopmail is vulnerable to several unspecified SQL injection exploits.
    Furthermore when using Sybase as the backend database vpopmail is
    vulnerable to a buffer overflow and format string exploit.
  
Impact

    These vulnerabilities could allow an attacker to execute code with the
    permissions of the user running vpopmail.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of vpopmail.
  
References:
    http://sourceforge.net/forum/forum.php?forum_id=400873
    http://www.securityfocus.com/archive/1/371913/2004-08-15/2004-08-21/0


Solution: 
    All vpopmail users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-mail/vpopmail-5.4.6"
    # emerge ">=net-mail/vpopmail-5.4.6"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-01] vpopmail: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'vpopmail: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/vpopmail", unaffected: make_list("ge 5.4.6"), vulnerable: make_list("lt 5.4.6")
)) { security_hole(0); exit(0); }
