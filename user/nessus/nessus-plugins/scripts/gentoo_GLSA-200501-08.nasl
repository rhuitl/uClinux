# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16399);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200501-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-08
(phpGroupWare: Various vulnerabilities)


    Several flaws were discovered in phpGroupWare making it vulnerable to
    cross-site scripting attacks, SQL injection, and full path disclosure.
  
Impact

    These vulnerabilities could allow an attacker to perform cross-site
    scripting attacks, execute SQL queries, and disclose the full path of
    the web directory.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/384492


Solution: 
    All phpGroupWare users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpgroupware-0.9.16.004"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-08] phpGroupWare: Various vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpGroupWare: Various vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpgroupware", unaffected: make_list("ge 0.9.16.004"), vulnerable: make_list("lt 0.9.16.004")
)) { security_warning(0); exit(0); }
