# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16004);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-17");
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-17
(kfax: Multiple overflows in the included TIFF library)


    Than Ngo discovered that kfax contains a private copy of the TIFF
    library and is therefore subject to several known vulnerabilities (see
    References).
  
Impact

    A remote attacker could entice a user to view a carefully-crafted TIFF
    image file with kfax, which would potentially lead to execution of
    arbitrary code with the rights of the user running kfax.
  
Workaround

    The KDE Team recommends to remove the kfax binary as well as the
    kfaxpart.la KPart:
    rm /usr/kde/3.*/lib/kde3/kfaxpart.la
    rm /usr/kde/3.*/bin/kfax
    Note: This will render the kfax functionality useless, if kfax
    functionality is needed you should upgrade to the KDE 3.3.2 which is
    not stable at the time of this writing.
    There is no known workaround at this time.
  
References:
    http://www.kde.org/info/security/advisory-20041209-2.txt
    http://www.gentoo.org/security/en/glsa/glsa-200410-11.xml
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0803
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0804
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0886


Solution: 
    All kfax users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdegraphics-3.3.2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-17] kfax: Multiple overflows in the included TIFF library");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'kfax: Multiple overflows in the included TIFF library');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdegraphics", unaffected: make_list("ge 3.3.2"), vulnerable: make_list("lt 3.3.2")
)) { security_warning(0); exit(0); }
