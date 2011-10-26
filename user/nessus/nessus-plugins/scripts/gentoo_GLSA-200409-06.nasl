# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14653);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-06");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-06
(eGroupWare: Multiple XSS vulnerabilities)


    Joxean Koret recently discovered multiple cross site scripting
    vulnerabilities in various modules for the eGroupWare suite. This includes
    the calendar, address book, messenger and ticket modules.
  
Impact

    These vulnerabilities give an attacker the ability to inject and execute
    malicious script code, potentially compromising the victim\'s browser.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of eGroupWare.
  
References:
    https://sourceforge.net/forum/forum.php?forum_id=401807
    http://www.securityfocus.com/archive/1/372603/2004-08-21/2004-08-27/0


Solution: 
    All eGroupWare users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=www-apps/egroupware-1.0.00.004"
    # emerge ">=www-apps/egroupware-1.0.00.004"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-06] eGroupWare: Multiple XSS vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'eGroupWare: Multiple XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/egroupware", unaffected: make_list("ge 1.0.00.004"), vulnerable: make_list("le 1.0.00.003")
)) { security_warning(0); exit(0); }
