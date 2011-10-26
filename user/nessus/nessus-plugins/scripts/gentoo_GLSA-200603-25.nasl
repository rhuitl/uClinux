# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-25.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21160);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-25");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-25
(OpenOffice.org: Heap overflow in included libcurl)


    OpenOffice.org includes libcurl code. This libcurl code is
    vulnerable to a heap overflow when it tries to parse a URL that exceeds
    a 256-byte limit (GLSA 200512-09).
  
Impact

    An attacker could entice a user to call a specially crafted URL
    with OpenOffice.org, potentially resulting in the execution of
    arbitrary code with the rights of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4077
    http://www.hardened-php.net/advisory_242005.109.html
    http://www.gentoo.org/security/en/glsa/glsa-200512-09.xml


Solution: 
    All OpenOffice.org binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-bin-2.0.2"
    All OpenOffice.org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-2.0.1-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-25] OpenOffice.org: Heap overflow in included libcurl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenOffice.org: Heap overflow in included libcurl');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-office/openoffice-bin", unaffected: make_list("ge 2.0.2"), vulnerable: make_list("lt 2.0.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice", unaffected: make_list("ge 2.0.1-r1"), vulnerable: make_list("lt 2.0.1-r1")
)) { security_warning(0); exit(0); }
