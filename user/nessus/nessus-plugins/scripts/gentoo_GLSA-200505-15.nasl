# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18379);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200505-15");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-15
(gdb: Multiple vulnerabilities)


    Tavis Ormandy of the Gentoo Linux Security Audit Team discovered
    an integer overflow in the BFD library, resulting in a heap overflow. A
    review also showed that by default, gdb insecurely sources
    initialisation files from the working directory.
  
Impact

    Successful exploitation would result in the execution of arbitrary
    code on loading a specially crafted object file or the execution of
    arbitrary commands.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All gdb users should upgrade to the latest stable version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-devel/gdb-6.3-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-15] gdb: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gdb: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-devel/gdb", unaffected: make_list("ge 6.3-r3"), vulnerable: make_list("lt 6.3-r3")
)) { security_warning(0); exit(0); }
