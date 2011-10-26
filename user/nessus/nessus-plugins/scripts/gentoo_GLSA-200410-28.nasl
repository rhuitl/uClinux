# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-28.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15580);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-28");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-28
(rssh: Format string vulnerability)


    Florian Schilhabel from the Gentoo Linux Security Audit Team found a format
    string vulnerability in rssh syslogging of failed commands.
  
Impact

    Using a malicious command, it may be possible for a remote authenticated
    user to execute arbitrary code on the target machine with user rights,
    effectively bypassing any restriction of rssh.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.pizzashack.org/rssh/security.shtml


Solution: 
    All rssh users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-shells/rssh-2.2.2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-28] rssh: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rssh: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-shells/rssh", unaffected: make_list("ge 2.2.2"), vulnerable: make_list("lt 2.2.2")
)) { security_hole(0); exit(0); }
