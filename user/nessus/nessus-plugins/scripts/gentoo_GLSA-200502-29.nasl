# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-29.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17206);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200502-29");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-29
(Cyrus IMAP Server: Multiple overflow vulnerabilities)


    Possible single byte overflows have been found in the imapd
    annotate extension and mailbox handling code. Furthermore stack buffer
    overflows have been found in fetchnews, the backend and imapd.
  
Impact

    An attacker, who could be an authenticated user or an admin of a
    peering news server, could exploit these vulnerabilities to execute
    arbitrary code with the rights of the user running the Cyrus IMAP
    Server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://asg.web.cmu.edu/archive/message.php?mailbox=archive.info-cyrus&msg=33723


Solution: 
    All Cyrus IMAP Server users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/cyrus-imapd-2.2.12"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-29] Cyrus IMAP Server: Multiple overflow vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cyrus IMAP Server: Multiple overflow vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/cyrus-imapd", unaffected: make_list("ge 2.2.12"), vulnerable: make_list("lt 2.2.12")
)) { security_warning(0); exit(0); }
