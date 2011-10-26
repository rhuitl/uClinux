# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17317);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200503-15");
 script_cve_id("CVE-2005-0605");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200503-15
(X.org: libXpm vulnerability)


    Chris Gilbert has discovered potentially exploitable buffer overflow
    cases in libXpm that weren\'t fixed in previous libXpm versions.
  
Impact

    A carefully-crafted XPM file could crash X.org, potentially allowing
    the execution of arbitrary code with the privileges of the user running
    the application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0605
    https://bugs.freedesktop.org/show_bug.cgi?id=1920


Solution: 
    All X.org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose x11-base/xorg-x11
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200503-15] X.org: libXpm vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'X.org: libXpm vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-base/xorg-x11", unaffected: make_list("rge 6.8.0-r5", "ge 6.8.2-r1"), vulnerable: make_list("lt 6.8.2-r1")
)) { security_warning(0); exit(0); }
