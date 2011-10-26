# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19535);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200508-15");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200508-15
(Apache 2.0: Denial of Service vulnerability)


    Filip Sneppe discovered that Apache improperly handles byterange
    requests to CGI scripts.
  
Impact

    A remote attacker may access vulnerable scripts in a malicious
    way, exhausting all RAM and swap space on the server, resulting in a
    Denial of Service of the Apache server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://issues.apache.org/bugzilla/show_bug.cgi?id=29962


Solution: 
    All apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/apache-2.0.54-r9"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200508-15] Apache 2.0: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 2.0: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/apache", unaffected: make_list("ge 2.0.54-r9", "lt 2.0"), vulnerable: make_list("lt 2.0.54-r9")
)) { security_warning(0); exit(0); }
