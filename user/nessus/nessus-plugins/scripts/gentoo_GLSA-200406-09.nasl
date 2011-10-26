# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14520);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200406-09");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-09
(Horde-Chora: Remote code execution)


    A vulnerability in the diff viewer of Chora allows an attacker to inject
    shellcode. An attacker can exploit PHP\'s file upload functionality to
    upload a malicious binary to a vulnerable server, chmod it as executable,
    and run the file.
  
Impact

    An attacker could remotely execute arbitrary binaries with the permissions
    of the PHP script, conceivably allowing further exploitation of local
    vulnerabilities and remote root access.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://security.e-matters.de/advisories/102004.html


Solution: 
    All users are advised to upgrade to the latest version of Chora:
    # emerge sync
    # emerge -pv ">=net-www/horde-chora-1.2.2"
    # emerge ">=net-www/horde-chora-1.2.2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-09] Horde-Chora: Remote code execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde-Chora: Remote code execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/horde-chora", unaffected: make_list("ge 1.2.2"), vulnerable: make_list("lt 1.2.2")
)) { security_hole(0); exit(0); }
