# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14569);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-13");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-13
(kdebase, kdelibs: Multiple security issues)


    KDE contains three security issues:
    Insecure handling of temporary files when running KDE applications
    outside of the KDE environment
    DCOPServer creates temporary files in an insecure manner
    The Konqueror browser allows websites to load webpages into a target
    frame of any other open frame-based webpage
  
Impact

    An attacker could exploit these vulnerabilities to create or overwrite
    files with the permissions of another user, compromise the account of users
    running a KDE application and insert arbitrary frames into an otherwise
    trusted webpage.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of kdebase.
  
References:
    http://www.kde.org/info/security/advisory-20040811-1.txt
    http://www.kde.org/info/security/advisory-20040811-2.txt
    http://www.kde.org/info/security/advisory-20040811-3.txt


Solution: 
    All KDE users should upgrade to the latest versions of kdelibs and kdebase:
    # emerge sync
    # emerge -pv ">=kde-base/kdebase-3.2.3-r1"
    # emerge ">=kde-base/kdebase-3.2.3-r1"
    # emerge -pv ">=kde-base/kdelibs-3.2.3-r1"
    # emerge ">=kde-base/kdelibs-3.2.3-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-13] kdebase, kdelibs: Multiple security issues");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'kdebase, kdelibs: Multiple security issues');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("ge 3.2.3-r1"), vulnerable: make_list("lt 3.2.3-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "kde-base/kdebase", unaffected: make_list("ge 3.2.3-r1"), vulnerable: make_list("lt 3.2.3-r1")
)) { security_warning(0); exit(0); }
