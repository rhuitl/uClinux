# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14456);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200403-05");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200403-05
(UUDeview MIME Buffer Overflow)


    By decoding a MIME archive with excessively long strings for various
    parameters, it is possible to crash UUDeview, or cause it to execute
    arbitrary code.
    This vulnerability was originally reported by iDEFENSE as part of a WinZip
    advisory [ Reference: 1 ].
  
Impact

    An attacker could create a specially-crafted MIME file and send it via
    email. When recipient decodes the file, UUDeview may execute arbitrary code
    which is embedded in the MIME file, thus granting the attacker access to
    the recipient\'s account.
  
Workaround

    There is no known workaround at this time. As a result, a software upgrade
    is required and users should upgrade to uudeview 0.5.20.
  
References:
    http://www.idefense.com/application/poi/display?id=76&type=vulnerabilities
    http://www.securityfocus.com/bid/9758


Solution: 
    All users should upgrade to uudeview 0.5.20:
    # emerge sync
    # emerge -pv ">=app-text/uudeview-0.5.20"
    # emerge ">=app-text/uudeview-0.5.20"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200403-05] UUDeview MIME Buffer Overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'UUDeview MIME Buffer Overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-text/uudeview", unaffected: make_list("ge 0.5.20"), vulnerable: make_list("lt 0.5.20")
)) { security_warning(0); exit(0); }
