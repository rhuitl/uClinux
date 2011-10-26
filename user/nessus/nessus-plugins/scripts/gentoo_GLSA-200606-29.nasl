# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-29.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21775);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-29");
 script_cve_id("CVE-2006-3048", "CVE-2006-3047");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-29
(Tikiwiki: SQL injection and multiple XSS vulnerabilities)


    Tikiwiki fails to properly sanitize user input before processing it,
    including in SQL statements.
  
Impact

    An attacker could execute arbitrary SQL statements on the underlying
    database, or inject arbitrary scripts into the context of a user\'s
    browser.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3048
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3047


Solution: 
    All Tikiwiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/tikiwiki-1.9.4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-29] Tikiwiki: SQL injection and multiple XSS vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tikiwiki: SQL injection and multiple XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/tikiwiki", unaffected: make_list("ge 1.9.4"), vulnerable: make_list("lt 1.9.4")
)) { security_warning(0); exit(0); }
