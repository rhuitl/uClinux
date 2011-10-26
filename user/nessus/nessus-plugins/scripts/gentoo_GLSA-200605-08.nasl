# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21350);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-08");
 script_cve_id("CVE-2006-0996", "CVE-2006-1490", "CVE-2006-1990", "CVE-2006-1991");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-08
(PHP: Multiple vulnerabilities)


    Several vulnerabilities were discovered on PHP4 and PHP5 by
    Infigo, Tonu Samuel and Maksymilian Arciemowicz. These included a
    buffer overflow in the wordwrap() function, restriction bypasses in the
    copy() and tempname() functions, a cross-site scripting issue in the
    phpinfo() function, a potential crash in the substr_compare() function
    and a memory leak in the non-binary-safe html_entity_decode() function.
  
Impact

    Remote attackers might be able to exploit these issues in PHP
    applications making use of the affected functions, potentially
    resulting in the execution of arbitrary code, Denial of Service,
    execution of scripted contents in the context of the affected site,
    security bypass or information leak.
  
Workaround

    There is no known workaround at this point.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0996
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1490
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1990
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1991


Solution: 
    All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-5.1.4"
    PHP4 users that wish to keep that version line should upgrade
    to the latest 4.x version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =dev-lang/php-4.4.2-r2
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-08] PHP: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/php", unaffected: make_list("ge 5.1.4", "rge 4.4.2-r2"), vulnerable: make_list("lt 5.1.4")
)) { security_hole(0); exit(0); }
