# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16413);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-22");
 script_cve_id("CVE-2005-0002");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-22
(poppassd_pam: Unauthorized password changing)


    Gentoo Linux developer Marcus Hanwell discovered that poppassd_pam
    did not check that the old password was valid before changing
    passwords. Our investigation revealed that poppassd_pam did not call
    pam_authenticate before calling pam_chauthtok.
  
Impact

    A remote attacker could change the system password of any user,
    including root. This leads to a complete compromise of the POP
    accounts, and may also lead to a complete root compromise of the
    affected server, if it also provides shell access authenticated using
    system passwords.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0002


Solution: 
    All poppassd_pam users should migrate to the new package called
    poppassd_ceti:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/poppassd_ceti-1.8.4"
    Note: Portage will automatically replace the poppassd_pam
    package by the poppassd_ceti package.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-22] poppassd_pam: Unauthorized password changing");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'poppassd_pam: Unauthorized password changing');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/poppassd_ceti", unaffected: make_list("ge 1.8.4"), vulnerable: make_list("le 1.0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-mail/poppassd_pam", unaffected: make_list(), vulnerable: make_list("le 1.0")
)) { security_hole(0); exit(0); }
