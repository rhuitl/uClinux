# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21664);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-02");
 script_cve_id("CVE-2006-1174");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-02
(shadow: Privilege escalation)


    When the mailbox is created in useradd, the "open()" function does
    not receive the three arguments it expects while O_CREAT is present,
    which leads to random permissions on the created file, before fchmod()
    is executed.
  
Impact

    Depending on the random permissions given to the mailbox file
    which is at this time owned by root, a local user may be able to open
    this file for reading or writing, or even executing it, maybe as the
    root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1174


Solution: 
    All shadow users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/shadow-4.0.15-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-02] shadow: Privilege escalation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'shadow: Privilege escalation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-apps/shadow", unaffected: make_list("ge 4.0.15-r2"), vulnerable: make_list("lt 4.0.15-r2")
)) { security_warning(0); exit(0); }
