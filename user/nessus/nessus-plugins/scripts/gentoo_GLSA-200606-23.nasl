# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-23.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21743);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-23");
 script_cve_id("CVE-2006-2449");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-23
(KDM: Symlink vulnerability)


    Ludwig Nussel discovered that KDM could be tricked into allowing users
    to read files that would otherwise not be readable.
  
Impact

    A local attacker could exploit this issue to obtain potentially
    sensitive information that is usually not accessable to the local user
    such as shadow files or other user\'s files. The default Gentoo user
    running KDM is root and, as a result, the local attacker can read any
    file.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.kde.org/info/security/advisory-20060614-1.txt
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2449


Solution: 
    All kdebase users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdebase
    All KDE split ebuild users should upgrade to the latest KDM version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/kdm
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-23] KDM: Symlink vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KDM: Symlink vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kdebase", unaffected: make_list("ge 3.5.2-r2", "rge 3.4.3-r2"), vulnerable: make_list("lt 3.5.2-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "kde-base/kdm", unaffected: make_list("ge 3.5.2-r2", "rge 3.4.3-r2"), vulnerable: make_list("lt 3.5.2-r2")
)) { security_warning(0); exit(0); }
