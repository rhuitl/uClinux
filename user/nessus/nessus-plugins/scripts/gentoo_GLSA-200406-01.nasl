# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14512);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200406-01");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-01
(Ethereal: Multiple security problems)


    There are multiple vulnerabilities in versions of Ethereal earlier than
    0.10.4, including:
    A buffer overflow in the MMSE dissector.
    Under specific conditions a SIP packet could make Ethereal crash.
    The AIM dissector could throw an assertion, causing Ethereal to
    crash.
    The SPNEGO dissector could dereference a null pointer, causing a
    crash.
  
Impact

    An attacker could use these vulnerabilities to crash Ethereal or even
    execute arbitrary code with the permissions of the user running Ethereal,
    which could be the root user.
  
Workaround

    For a temporary workaround you can disable all affected protocol dissectors
    by selecting Analyze->Enabled Protocols... and deselecting them from the
    list. However, it is strongly recommended to upgrade to the latest stable
    release.
  
References:
    http://www.ethereal.com/appnotes/enpa-sa-00014.html


Solution: 
    All Ethereal users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-analyzer/ethereal-0.10.4"
    # emerge ">=net-analyzer/ethereal-0.10.4"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-01] Ethereal: Multiple security problems");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ethereal: Multiple security problems');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list("ge 0.10.4"), vulnerable: make_list("le 0.10.3")
)) { security_hole(0); exit(0); }
