# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-28.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15776);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-28");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-28
(X.Org, XFree86: libXpm vulnerabilities)


    Several issues were discovered in libXpm, including integer
    overflows, out-of-bounds memory accesses, insecure path traversal and
    an endless loop.
  
Impact

    An attacker could craft a malicious pixmap file and entice a user
    to use it with an application linked against libXpm. This could lead to
    Denial of Service or arbitrary code execution.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0914


Solution: 
    All X.Org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xorg-x11-6.7.0-r3"
    All XFree86 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-base/xfree-x11-4.3.0-r8"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-28] X.Org, XFree86: libXpm vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.Org, XFree86: libXpm vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-base/xorg-x11", unaffected: make_list("ge 6.8.0-r3", "rge 6.7.0-r3"), vulnerable: make_list("lt 6.8.0-r3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-base/xfree", unaffected: make_list("ge 4.3.0-r8"), vulnerable: make_list("lt 4.3.0-r8")
)) { security_warning(0); exit(0); }
