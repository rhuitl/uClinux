# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14484);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200404-19");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200404-19
(Buffer overflows and format string vulnerabilities in LCDproc)


    Due to insufficient checking of client-supplied data, the LCDd server is
    susceptible to two buffer overflows and one string buffer vulnerability. If
    the server is configured to listen on all network interfaces (see the Bind
    parameter in LCDproc configuration), these vulnerabilities can be triggered
    remotely.
  
Impact

    These vulnerabilities allow an attacker to execute code with the rights of
    the user running the LCDproc server. By default, this is the "nobody" user.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
References:
    http://lists.omnipotent.net/pipermail/lcdproc/2004-April/008884.html


Solution: 
    LCDproc users should upgrade to version 0.4.5 or later:
    # emerge sync
    # emerge -pv ">=app-misc/lcdproc-0.4.5"
    # emerge ">=app-misc/lcdproc-0.4.5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200404-19] Buffer overflows and format string vulnerabilities in LCDproc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Buffer overflows and format string vulnerabilities in LCDproc');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-misc/lcdproc", unaffected: make_list("ge 0.4.5"), vulnerable: make_list("le 0.4.4-r1")
)) { security_warning(0); exit(0); }
