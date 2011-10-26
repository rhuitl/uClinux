# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16010);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200412-20");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200412-20
(NASM: Buffer overflow vulnerability)


    Jonathan Rockway discovered that NASM-0.98.38 has an unprotected
    vsprintf() to an array in preproc.c. This code vulnerability may lead
    to a buffer overflow and potential execution of arbitrary code.
  
Impact

    A remote attacker could craft a malicious object file which, when
    supplied in NASM, would result in the execution of arbitrary code with
    the rights of the user running NASM.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://sourceforge.net/mailarchive/forum.php?thread_id=6166881&forum_id=4978


Solution: 
    All NASM users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/nasm-0.98.38-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200412-20] NASM: Buffer overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'NASM: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-lang/nasm", unaffected: make_list("ge 0.98.38-r1"), vulnerable: make_list("le 0.98.38")
)) { security_warning(0); exit(0); }
