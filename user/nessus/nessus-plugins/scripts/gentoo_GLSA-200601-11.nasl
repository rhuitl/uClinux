# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20798);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-11");
 script_cve_id("CVE-2006-0019");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-11
(KDE kjs: URI heap overflow vulnerability)


    Maksim Orlovich discovered an incorrect bounds check in kjs when
    handling URIs.
  
Impact

    By enticing a user to load a specially crafted webpage containing
    malicious javascript, an attacker could execute arbitrary code with the
    rights of the user running kjs.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0019
    http://www.kde.org/info/security/advisory-20060119-1.txt


Solution: 
    All kdelibs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdelibs-3.4.3-r1
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-11] KDE kjs: URI heap overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KDE kjs: URI heap overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("ge 3.4.3-r1"), vulnerable: make_list("lt 3.4.3-r1")
)) { security_warning(0); exit(0); }
