# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18234);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200505-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-08
(HT Editor: Multiple buffer overflows)


    Tavis Ormandy of the Gentoo Linux Security Team discovered an
    integer overflow in the ELF parser, leading to a heap-based buffer
    overflow. The vendor has reported that an unrelated buffer overflow has
    been discovered in the PE parser.
  
Impact

    Successful exploitation would require the victim to open a
    specially crafted file using HT, potentially permitting an attacker to
    execute arbitrary code.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All hteditor users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/hteditor-0.8.0-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-08] HT Editor: Multiple buffer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'HT Editor: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-editors/hteditor", unaffected: make_list("ge 0.8.0-r2"), vulnerable: make_list("lt 0.8.0-r2")
)) { security_warning(0); exit(0); }
