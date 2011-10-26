# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15906);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-02");
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-02
(PDFlib: Multiple overflows in the included TIFF library)


    The TIFF library is subject to several known vulnerabilities (see
    GLSA 200410-11). Most of these overflows also apply to PDFlib.
  
Impact

    A remote attacker could entice a user or web application to
    process a carefully crafted PDF file or TIFF image using a
    PDFlib-powered program. This can potentially lead to the execution of
    arbitrary code with the rights of the program processing the file.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.pdflib.com/products/pdflib/info/PDFlib-5.0.4p1-changes.txt
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0803
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0804
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0886
    http://www.gentoo.org/security/en/glsa/glsa-200410-11.xml


Solution: 
    All PDFlib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/pdflib-5.0.4_p1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-02] PDFlib: Multiple overflows in the included TIFF library");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PDFlib: Multiple overflows in the included TIFF library');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/pdflib", unaffected: make_list("ge 5.0.4_p1"), vulnerable: make_list("lt 5.0.4_p1")
)) { security_warning(0); exit(0); }
