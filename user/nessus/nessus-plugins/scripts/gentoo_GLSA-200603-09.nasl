# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21047);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-09");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-09
(SquirrelMail: Cross-site scripting and IMAP command injection)


    SquirrelMail does not validate the right_frame parameter in
    webmail.php, possibly allowing frame replacement or cross-site
    scripting (CVE-2006-0188). Martijn Brinkers and Scott Hughes discovered
    that MagicHTML fails to handle certain input correctly, potentially
    leading to cross-site scripting (only Internet Explorer,
    CVE-2006-0195). Vicente Aguilera reported that the
    sqimap_mailbox_select function did not strip newlines from the mailbox
    or subject parameter, possibly allowing IMAP command injection
    (CVE-2006-0377).
  
Impact

    By exploiting the cross-site scripting vulnerabilities, an
    attacker can execute arbitrary scripts running in the context of the
    victim\'s browser. This could lead to a compromise of the user\'s webmail
    account, cookie theft, etc. A remote attacker could exploit the IMAP
    command injection to execute arbitrary IMAP commands on the configured
    IMAP server.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0188
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0195
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0377


Solution: 
    All SquirrelMail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/squirrelmail-1.4.6"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-09] SquirrelMail: Cross-site scripting and IMAP command injection");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SquirrelMail: Cross-site scripting and IMAP command injection');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/squirrelmail", unaffected: make_list("ge 1.4.6"), vulnerable: make_list("lt 1.4.6")
)) { security_warning(0); exit(0); }
