# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-34.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14821);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200409-34");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-34
(X.org, XFree86: Integer and stack overflows in libXpm)


    Chris Evans has discovered multiple integer and stack overflow
    vulnerabilities in the X Pixmap library, libXpm, which is a part of the X
    Window System. These overflows can be exploited by the execution of a
    malicious XPM file, which can crash applications that are dependent on
    libXpm.
  
Impact

    A carefully-crafted XPM file could crash applications that are linked
    against libXpm, potentially allowing the execution of arbitrary code with
    the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://freedesktop.org/pipermail/xorg/2004-September/003196.html
    http://freedesktop.org/pipermail/xorg/2004-September/003172.html
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0687
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0688


Solution: 
    All X.org users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=x11-base/xorg-x11-6.7.0-r2"
    # emerge ">=x11-base/xorg-x11-6.7.0-r2"
    All XFree86 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=x11-base/xfree-4.3.0-r7"
    # emerge ">=x11-base/xfree-4.3.0-r7"
    Note: Usage of XFree86 is deprecated on the AMD64, HPPA, IA64, MIPS, PPC
    and SPARC architectures: XFree86 users on those architectures should switch
    to X.org rather than upgrading XFree86.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-34] X.org, XFree86: Integer and stack overflows in libXpm");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.org, XFree86: Integer and stack overflows in libXpm');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-base/xorg-x11", unaffected: make_list("rge 6.7.0-r2", "ge 6.8.0-r1"), vulnerable: make_list("lt 6.7.0-r2", "eq 6.8.0")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-base/xfree", arch: "AMD64 HPPA IA64 MIPS PPC SPARC", unaffected: make_list(), vulnerable: make_list("lt 4.3.0-r7")
)) { security_warning(0); exit(0); }
