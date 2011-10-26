# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20267);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-23");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-23
(chmlib, KchmViewer: Stack-based buffer overflow)


    Sven Tantau reported about a buffer overflow vulnerability in
    chmlib. The function "_chm_decompress_block()" does not properly
    perform boundary checking, resulting in a stack-based buffer overflow.
  
Impact

    By convincing a user to open a specially crafted ITSS or CHM file,
    using KchmViewer or a program makes use of chmlib, a remote attacker
    could execute arbitrary code with the privileges of the user running
    the software.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3318


Solution: 
    All chmlib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-doc/chmlib-0.37.4"
    All KchmViewer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-doc/kchmviewer-1.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-23] chmlib, KchmViewer: Stack-based buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'chmlib, KchmViewer: Stack-based buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-doc/kchmviewer", unaffected: make_list("ge 1.1"), vulnerable: make_list("lt 1.1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-doc/chmlib", unaffected: make_list("ge 0.37.4"), vulnerable: make_list("lt 0.37.4")
)) { security_warning(0); exit(0); }
