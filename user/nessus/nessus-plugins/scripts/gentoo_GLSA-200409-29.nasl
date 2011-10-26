# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-29.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14797);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200409-29");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-29
(FreeRADIUS: Multiple Denial of Service vulnerabilities)


    There are undisclosed defects in the way FreeRADIUS handles incorrect
    received packets.
  
Impact

    A remote attacker could send specially-crafted packets to the FreeRADIUS
    server to deny service to other users by crashing the server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.freeradius.org/security.html


Solution: 
    All FreeRADIUS users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-dialup/freeradius-1.0.1"
    # emerge ">=net-dialup/freeradius-1.0.1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-29] FreeRADIUS: Multiple Denial of Service vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FreeRADIUS: Multiple Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-dialup/freeradius", unaffected: make_list("ge 1.0.1"), vulnerable: make_list("lt 1.0.1")
)) { security_warning(0); exit(0); }
