# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14544);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200407-11");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-11
(wv: Buffer overflow vulnerability)


    A use of strcat without proper bounds checking leads to an exploitable
    buffer overflow. The vulnerable code is executed when wv encounters an
    unrecognized token, so a specially crafted file, loaded in wv, can trigger
    the vulnerable code and execute it\'s own arbitrary code. This exploit is
    only possible when the user loads the document into HTML view mode.
  
Impact

    By inducing a user into running wv on a special file, an attacker can
    execute arbitrary code with the permissions of the user running the
    vulnerable program.
  
Workaround

    Users should not view untrusted documents with wvHtml or applications using
    wv. When loading an untrusted document in an application using the wv
    library, make sure HTML view is disabled.
  
References:
    http://www.idefense.com/application/poi/display?id=115&type=vulnerabilities&flashstatus=true


Solution: 
    All users should upgrade to the latest available version.
    # emerge sync
    # emerge -pv ">=app-text/wv-1.0.0-r1"
    # emerge ">=app-text/wv-1.0.0-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-11] wv: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'wv: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/wv", unaffected: make_list("ge 1.0.0-r1"), vulnerable: make_list("lt 1.0.0-r1")
)) { security_warning(0); exit(0); }
