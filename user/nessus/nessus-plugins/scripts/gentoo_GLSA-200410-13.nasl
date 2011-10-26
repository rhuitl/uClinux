# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15476);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-13");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-13
(BNC: Input validation flaw)


    A flaw exists in the input parsing of BNC where part of the sbuf_getmsg()
    function handles the backspace character incorrectly.
  
Impact

    A remote user could issue commands using fake authentication credentials
    and possibly gain access to scripts running on the client side.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.gotbnc.com/changes.html#2.8.9


Solution: 
    All BNC users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-irc/bnc-2.8.9"
    # emerge ">=net-irc/bnc-2.8.9"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-13] BNC: Input validation flaw");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'BNC: Input validation flaw');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-irc/bnc", unaffected: make_list("ge 2.8.9"), vulnerable: make_list("lt 2.8.9")
)) { security_warning(0); exit(0); }
