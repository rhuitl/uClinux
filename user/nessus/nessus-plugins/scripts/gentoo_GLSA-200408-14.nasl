# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-14.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14570);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-14");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-14
(acroread: UUDecode filename buffer overflow)


    acroread contains two errors in the handling of UUEncoded filenames. First,
    it fails to check the length of a filename before copying it into a fixed
    size buffer and, secondly, it fails to check for the backtick shell
    metacharacter in the filename before executing a command with a shell.
  
Impact

    By enticing a user to open a PDF with a specially crafted filename, an
    attacker could execute arbitrary code or programs with the permissions of
    the user running acroread.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of acroread.
  
References:
    http://idefense.com/application/poi/display?id=124&type=vulnerabilities
    http://idefense.com/application/poi/display?id=125&type=vulnerabilities


Solution: 
    All acroread users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=app-text/acroread-5.09"
    # emerge ">=app-text/acroread-5.09"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-14] acroread: UUDecode filename buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'acroread: UUDecode filename buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/acroread", unaffected: make_list("ge 5.09"), vulnerable: make_list("le 5.08")
)) { security_warning(0); exit(0); }
