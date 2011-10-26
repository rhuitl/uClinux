# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-39.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16430);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-39");
 script_cve_id("CVE-2005-0075", "CVE-2005-0103", "CVE-2005-0104");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-39
(SquirrelMail: Multiple vulnerabilities)


    SquirrelMail fails to properly sanitize certain strings when
    decoding specially-crafted strings, which can lead to PHP file
    inclusion and XSS.
    Insufficient checking of incoming URLs
    in prefs.php (CVE-2005-0075) and in webmail.php (CVE-2005-0103).
    Insufficient escaping of integers in webmail.php
    (CVE-2005-0104).
  
Impact

    By sending a specially-crafted URL, an attacker can execute
    arbitrary code from the local system with the permissions of the web
    server. Furthermore by enticing a user to load a specially-crafted URL,
    it is possible to display arbitrary remote web pages in Squirrelmail\'s
    frameset and execute arbitrary scripts running in the context of the
    victim\'s browser. This could lead to a compromise of the user\'s webmail
    account, cookie theft, etc.
  
Workaround

    The arbitrary code execution is only possible with
    "register_globals" set to "On". Gentoo ships PHP with
    "register_globals" set to "Off" by default. There are no known
    workarounds for the other issues at this time.
  
References:
    http://sourceforge.net/mailarchive/message.php?msg_id=10628451
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0075
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0103
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0104


Solution: 
    All SquirrelMail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/squirrelmail-1.4.4"
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-39] SquirrelMail: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SquirrelMail: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "mail-client/squirrelmail", unaffected: make_list("ge 1.4.4"), vulnerable: make_list("le 1.4.3a-r2")
)) { security_hole(0); exit(0); }
