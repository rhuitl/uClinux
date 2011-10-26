# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20962);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-12");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-12
(GPdf: heap overflows in included Xpdf code)


    Dirk Mueller found a heap overflow vulnerability in the XPdf
    codebase when handling splash images that exceed size of the associated
    bitmap.
  
Impact

    An attacker could entice a user to open a specially crafted PDF
    file with GPdf, potentially resulting in the execution of arbitrary
    code with the rights of the user running the affected application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0301


Solution: 
    All GPdf users should upgrade to the latest version.
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/gpdf-2.10.0-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-12] GPdf: heap overflows in included Xpdf code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GPdf: heap overflows in included Xpdf code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/gpdf", unaffected: make_list("ge 2.10.0-r4"), vulnerable: make_list("lt 2.10.0-r4")
)) { security_warning(0); exit(0); }
