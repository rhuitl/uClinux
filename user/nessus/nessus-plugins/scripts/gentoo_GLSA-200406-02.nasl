# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14513);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200406-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200406-02
(tripwire: Format string vulnerability)


    The code that generates email reports contains a format string
    vulnerability in pipedmailmessage.cpp.
  
Impact

    With a carefully crafted filename on a local filesystem an attacker could
    cause execution of arbitrary code with permissions of the user running
    tripwire, which could be the root user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/365036/2004-05-31/2004-06-06/0


Solution: 
    All tripwire users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=app-admin/tripwire-2.3.1.2-r1"
    # emerge ">=app-admin/tripwire-2.3.1.2-r1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200406-02] tripwire: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'tripwire: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-admin/tripwire", unaffected: make_list("ge 2.3.1.2-r1"), vulnerable: make_list("le 2.3.1.2")
)) { security_hole(0); exit(0); }
