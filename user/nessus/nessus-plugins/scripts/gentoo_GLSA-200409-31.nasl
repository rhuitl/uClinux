# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-31.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14799);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200409-31");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-31
(jabberd 1.x: Denial of Service vulnerability)


    Jose Antonio Calvo found a defect in routines handling XML parsing of
    incoming data. jabberd 1.x may crash upon reception of invalid data on any
    socket connection on which XML is parsed.
  
Impact

    A remote attacker may send a specific sequence of bytes to an open socket
    to crash the jabberd server, resulting in a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.jabber.org/pipermail/jabberd/2004-September/002004.html
    http://www.jabber.org/pipermail/jadmin/2004-September/018046.html


Solution: 
    All jabberd users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-im/jabberd-1.4.3-r4"
    # emerge ">=net-im/jabberd-1.4.3-r4"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-31] jabberd 1.x: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'jabberd 1.x: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/jabberd", unaffected: make_list("ge 1.4.3-r4"), vulnerable: make_list("le 1.4.3-r3")
)) { security_warning(0); exit(0); }
