# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20411);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200601-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200601-01
(pinentry: Local privilege escalation)


    Tavis Ormandy of the Gentoo Linux Security Audit Team has
    discovered that the pinentry ebuild incorrectly sets the permissions of
    the pinentry binaries upon installation, so that the sgid bit is set
    making them execute with the privileges of group ID 0.
  
Impact

    A user of pinentry could potentially read and overwrite files with
    a group ID of 0.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All pinentry users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/pinentry-0.7.2-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200601-01] pinentry: Local privilege escalation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'pinentry: Local privilege escalation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/pinentry", unaffected: make_list("ge 0.7.2-r2"), vulnerable: make_list("lt 0.7.2-r2")
)) { security_warning(0); exit(0); }
