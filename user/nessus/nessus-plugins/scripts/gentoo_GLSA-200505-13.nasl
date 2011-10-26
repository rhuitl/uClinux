# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200505-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18272);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200505-13");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200505-13
(FreeRADIUS: SQL injection and Denial of Service vulnerability)


    Primoz Bratanic discovered that the sql_escape_func function of
    FreeRADIUS may be vulnerable to a buffer overflow (BID 13541). He also
    discovered that FreeRADIUS fails to sanitize user-input before using it
    in a SQL query, possibly allowing SQL command injection (BID 13540).
  
Impact

    By supplying carefully crafted input, a malicious user could cause an
    SQL injection or a buffer overflow, possibly leading to the disclosure
    and the modification of sensitive data or Denial of Service by crashing
    the server.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://www.securityfocus.com/bid/13540/
    http://www.securityfocus.com/bid/13541/


Solution: 
    All FreeRADIUS users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dialup/freeradius-1.0.2-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200505-13] FreeRADIUS: SQL injection and Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FreeRADIUS: SQL injection and Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-dialup/freeradius", unaffected: make_list("ge 1.0.2-r4"), vulnerable: make_list("lt 1.0.2-r4")
)) { security_warning(0); exit(0); }
