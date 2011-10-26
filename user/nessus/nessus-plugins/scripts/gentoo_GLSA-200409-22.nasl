# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14767);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200409-22");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-22
(phpGroupWare: XSS vulnerability in wiki module)


    Due to an input validation error, the wiki module in the phpGroupWare suite
    is vulnerable to cross site scripting attacks.
  
Impact

    This vulnerability gives an attacker the ability to inject and execute
    malicious script code, potentially compromising the victim\'s browser.
  
Workaround

    The is no known workaround at this time.
  
References:
    http://downloads.phpgroupware.org/changelog
    http://secunia.com/advisories/12466/


Solution: 
    All phpGroupWare users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=www-apps/phpgroupware-0.9.16.003"
    # emerge ">=www-apps/phpgroupware-0.9.16.003"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-22] phpGroupWare: XSS vulnerability in wiki module");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpGroupWare: XSS vulnerability in wiki module');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpgroupware", unaffected: make_list("ge 0.9.16.003"), vulnerable: make_list("lt 0.9.16.003")
)) { security_warning(0); exit(0); }
