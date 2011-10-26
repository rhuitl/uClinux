# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-24.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18127);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200504-24");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200504-24
(eGroupWare: XSS and SQL injection vulnerabilities)


    Multiple SQL injection and cross-site scripting vulnerabilities
    have been found in several eGroupWare modules.
  
Impact

    An attacker could possibly use the SQL injection vulnerabilites to
    gain information from the database. Furthermore the cross-site
    scripting issues give an attacker the ability to inject and execute
    malicious script code or to steal cookie based authentication
    credentials, potentially compromising the victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.gulftech.org/?node=research&article_id=00069-04202005


Solution: 
    All eGroupWare users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/egroupware-1.0.0.007"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200504-24] eGroupWare: XSS and SQL injection vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'eGroupWare: XSS and SQL injection vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/egroupware", unaffected: make_list("ge 1.0.0.007"), vulnerable: make_list("lt 1.0.0.007")
)) { security_warning(0); exit(0); }
