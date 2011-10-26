# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15954);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200412-07");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-07
(file: Arbitrary code execution)


    A possible stack overflow has been found in the ELF header parsing
    code of file.
  
Impact

    An attacker may be able to create a specially crafted ELF file
    which, when processed with file, may allow the execution of arbitrary
    code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://securitytracker.com/id?1012433


Solution: 
    All file users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/file-4.12"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-07] file: Arbitrary code execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'file: Arbitrary code execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-apps/file", unaffected: make_list("ge 4.12"), vulnerable: make_list("lt 4.12")
)) { security_warning(0); exit(0); }
