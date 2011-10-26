# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20030);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200510-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-10
(uw-imap: Remote buffer overflow)


    Improper bounds checking of user supplied data while parsing IMAP
    mailbox names can lead to overflowing the stack buffer.
  
Impact

    Successful exploitation requires an authenticated IMAP user to
    request a malformed mailbox name. This can lead to execution of
    arbitrary code with the permissions of the IMAP server.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2933
    http://www.idefense.com/application/poi/display?id=313&type=vulnerabilities&flashstatus=false


Solution: 
    All uw-imap users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/uw-imap-2004g"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-10] uw-imap: Remote buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'uw-imap: Remote buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/uw-imap", unaffected: make_list("ge 2004g"), vulnerable: make_list("lt 2004g")
)) { security_hole(0); exit(0); }
