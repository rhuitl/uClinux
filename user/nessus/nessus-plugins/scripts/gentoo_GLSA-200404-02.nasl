# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14467);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200404-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-02
(KDE Personal Information Management Suite Remote Buffer Overflow Vulnerability)


    A buffer overflow may occur in KDE-PIM\'s VCF file reader when a maliciously
    crafted VCF file is opened by a user on a vulnerable system.
  
Impact

    A remote attacker may unauthorized access to a user\'s personal data or
    execute commands with the user\'s privileges.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0988


Solution: 
    KDE users should upgrade to version 3.1.5 or later:
    # emerge sync
    # emerge -pv ">=kde-base/kde-3.1.5"
    # emerge ">=kde-base/kde-3.1.5"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-02] KDE Personal Information Management Suite Remote Buffer Overflow Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KDE Personal Information Management Suite Remote Buffer Overflow Vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/kde", unaffected: make_list("ge 3.1.5"), vulnerable: make_list("le 3.1.4")
)) { security_hole(0); exit(0); }
