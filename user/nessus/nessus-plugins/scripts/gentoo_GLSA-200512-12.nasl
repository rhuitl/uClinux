# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20353);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200512-12");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200512-12
(Mantis: Multiple vulnerabilities)


    Tobias Klein discovered that Mantis contains several
    vulnerabilities, including:
    a file upload
    vulnerability.
    an injection vulnerability in filters.
    an SQL injection vulnerability in the user-management page.
    a port cross-site-scripting vulnerability in filters.
    an
    HTTP header CRLF injection vulnerability.
  
Impact

    An attacker could possibly exploit the file upload vulnerability
    to execute arbitrary script code, and the SQL injection vulnerability
    to access or modify sensitive information from the Mantis database.
    Furthermore, the cross-site scripting and HTTP response splitting may
    allow an attacker to inject and execute malicious script code or to
    steal cookie-based authentication credentials, potentially compromising
    the victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.mantisbt.org/changelog.php


Solution: 
    All Mantis users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/mantisbt-0.19.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200512-12] Mantis: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mantis: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/mantisbt", unaffected: make_list("ge 0.19.4"), vulnerable: make_list("lt 0.19.4")
)) { security_warning(0); exit(0); }
