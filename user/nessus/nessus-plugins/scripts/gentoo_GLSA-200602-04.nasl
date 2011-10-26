# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20894);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-04");
 script_cve_id("CVE-2006-0301");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-04
(Xpdf, Poppler: Heap overflow)


    Dirk Mueller has reported a vulnerability in Xpdf. It is caused by
    a missing boundary check in the splash rasterizer engine when handling
    PDF splash images with overly large dimensions.
  
Impact

    By sending a specially crafted PDF file to a victim, an attacker
    could cause an overflow, potentially resulting in the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0301


Solution: 
    All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/xpdf-3.01-r7"
    All Poppler users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/poppler-0.5.0-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-04] Xpdf, Poppler: Heap overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xpdf, Poppler: Heap overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/xpdf", unaffected: make_list("ge 3.01-r7"), vulnerable: make_list("lt 3.01-r7")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/poppler", unaffected: make_list("ge 0.5.0-r4"), vulnerable: make_list("lt 0.5.0-r4")
)) { security_warning(0); exit(0); }
