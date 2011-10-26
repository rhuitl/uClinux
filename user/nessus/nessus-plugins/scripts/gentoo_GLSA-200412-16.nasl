# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16003);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-16");
 script_cve_id("CVE-2004-1171", "CVE-2004-1158");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-16
(kdelibs, kdebase: Multiple vulnerabilities)


    Daniel Fabian discovered that the KDE core libraries contain a
    flaw allowing password disclosure by making a link to a remote file.
    When creating this link, the resulting URL contains authentication
    credentials used to access the remote file (CAN 2004-1171).
    The Konqueror webbrowser allows websites to load webpages into a window
    or tab currently used by another website (CVE-2004-1158).
  
Impact

    A malicious user could have access to the authentication
    credentials of other users depending on the file permissions.
    A malicious website could use the window injection vulnerability to
    load content in a window apparently belonging to another website.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.kde.org/info/security/advisory-20041209-1.txt
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1171
    http://www.kde.org/info/security/advisory-20041213-1.txt
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1158


Solution: 
    All kdelibs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdelibs-3.2.3-r4"
    All kdebase users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdebase-3.2.3-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-16] kdelibs, kdebase: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'kdelibs, kdebase: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdebase", unaffected: make_list("rge 3.2.3-r3", "rge 3.3.1-r2"), vulnerable: make_list("lt 3.3.2-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "kde-base/kdelibs", unaffected: make_list("rge 3.2.3-r4", "rge 3.3.1-r2", "ge 3.3.2-r1"), vulnerable: make_list("lt 3.3.2-r1")
)) { security_warning(0); exit(0); }
