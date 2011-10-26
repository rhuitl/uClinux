# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20197);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200511-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200511-10
(RAR: Format string and buffer overflow vulnerabilities)


    Tan Chew Keong reported about two vulnerabilities found in RAR:
    A format string error exists when displaying a diagnostic
    error message that informs the user of an invalid filename in an
    UUE/XXE encoded file.
    Some boundary errors in the processing
    of malicious ACE archives can be exploited to cause a buffer
    overflow.
  
Impact

    A remote attacker could exploit these vulnerabilities by enticing
    a user to:
    decode a specially crafted UUE/XXE file,
    or
    extract a malicious ACE archive containing a file with an
    overly long filename.
    When the user performs these
    actions, the arbitrary code of the attacker\'s choice will be executed.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.rarlabs.com/rarnew.htm
    http://secunia.com/secunia_research/2005-53/advisory/


Solution: 
    All RAR users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/rar-3.5.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200511-10] RAR: Format string and buffer overflow vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'RAR: Format string and buffer overflow vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/rar", unaffected: make_list("ge 3.5.1"), vulnerable: make_list("lt 3.5.1")
)) { security_warning(0); exit(0); }
