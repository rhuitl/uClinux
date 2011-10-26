# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200401-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14444);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200401-04");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200401-04
(GAIM 0.75 Remote overflows)


    Yahoo changed the authentication methods to their IM servers,
    rendering GAIM useless. The GAIM team released a rushed release
    solving this issue, however, at the same time a code audit
    revealed 12 new vulnerabilities.
  
Impact

    Due to the nature of instant messaging many of these bugs require
    man-in-the-middle attacks between the client and the server. But
    the underlying protocols are easy to implement and attacking
    ordinary TCP sessions is a fairly simple task. As a result, all
    users are advised to upgrade their GAIM installation.
        Users of GAIM 0.74 or below are affected by 7 of the
        vulnerabilities and are encouraged to upgrade.
        Users of GAIM 0.75 are affected by 11 of the vulnerabilities
        and are encouraged to upgrade to the patched version of GAIM
        offered by Gentoo.
        Users of GAIM 0.75-r6 are only affected by
        4 of the vulnerabilities, but are still urged to upgrade to
        maintain security.
  
Workaround

    There is no immediate workaround; a software upgrade is required.
  
References:
    http://www.securityfocus.com/archive/1/351235/2004-01-23/2004-01-29/0


Solution: 
    All users are recommended to upgrade GAIM to 0.75-r7.
    $> emerge sync
    $> emerge -pv ">=net-im/gaim-0.75-r7"
    $> emerge ">=net-im/gaim-0.75-r7"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200401-04] GAIM 0.75 Remote overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GAIM 0.75 Remote overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 0.75-r7"), vulnerable: make_list("lt 0.75-r7")
)) { security_warning(0); exit(0); }
