# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15903);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200412-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-01
(rssh, scponly: Unrestricted command execution)


    Jason Wies discovered that when receiving an authorized command from an
    authorized user, rssh and scponly do not filter command-line options
    that can be used to execute any command on the target host.
  
Impact

    Using a malicious command, it is possible for a remote authenticated
    user to execute any command (or upload and execute any file) on the
    target machine with user rights, effectively bypassing any restriction
    of scponly or rssh.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/383046/2004-11-30/2004-12-06/0


Solution: 
    All scponly users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/scponly-4.0"
    All rssh users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-shells/rssh/rssh-2.2.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-01] rssh, scponly: Unrestricted command execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rssh, scponly: Unrestricted command execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/scponly", unaffected: make_list("ge 4.0"), vulnerable: make_list("lt 4.0")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-shells/rssh", unaffected: make_list("ge 2.2.3"), vulnerable: make_list("le 2.2.2")
)) { security_warning(0); exit(0); }
