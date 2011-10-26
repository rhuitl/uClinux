# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21000);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-02
(teTeX, pTeX, CSTeX: Multiple overflows in included XPdf code)


    CSTeX, teTex, and pTeX include XPdf code to handle PDF files. This
    XPdf code is vulnerable to several heap overflows (GLSA 200512-08) as
    well as several buffer and integer overflows discovered by Chris Evans
    (CESA-2005-003).
  
Impact

    An attacker could entice a user to open a specially crafted PDF
    file with teTeX, pTeX or CSTeX, potentially resulting in the execution
    of arbitrary code with the rights of the user running the affected
    application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-3193
    http://www.gentoo.org/security/en/glsa/glsa-200512-08.xml
    http://scary.beasts.org/security/CESA-2005-003.txt


Solution: 
    All teTex users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/tetex-2.0.2-r8"
    All CSTeX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/cstetex-2.0.2-r2"
    All pTeX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/ptex-3.1.5-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-02] teTeX, pTeX, CSTeX: Multiple overflows in included XPdf code");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'teTeX, pTeX, CSTeX: Multiple overflows in included XPdf code');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/ptex", unaffected: make_list("ge 3.1.5-r1"), vulnerable: make_list("lt 3.1.5-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/tetex", unaffected: make_list("ge 2.0.2-r8"), vulnerable: make_list("lt 2.0.2-r8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/cstetex", unaffected: make_list("ge 2.0.2-r2"), vulnerable: make_list("lt 2.0.2-r2")
)) { security_warning(0); exit(0); }
