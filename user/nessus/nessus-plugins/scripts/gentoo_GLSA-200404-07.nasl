# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14472);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200404-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-07
(ClamAV RAR Archive Remote Denial Of Service Vulnerability)


    Certain types of RAR archives, including those created by variants of the
    W32.Beagle.A@mm worm, may cause clamav to crash when it attempts to process
    them.
  
Impact

    This vulnerability causes a Denial of Service in the clamav process.  Depending on
    configuration, this may cause dependent services such as mail to fail as well.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  

Solution: 
    ClamAV users should upgrade to version 0.68.1 or later:
    # emerge sync
    # emerge -pv ">=net-mail/clamav-0.68.1"
    # emerge ">=net-mail/clamav-0.68.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-07] ClamAV RAR Archive Remote Denial Of Service Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV RAR Archive Remote Denial Of Service Vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/clamav", unaffected: make_list("ge 0.68.1"), vulnerable: make_list("le 0.68")
)) { security_warning(0); exit(0); }
