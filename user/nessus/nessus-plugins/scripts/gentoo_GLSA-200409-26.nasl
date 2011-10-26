# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14781);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200409-26");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-26
(Mozilla, Firefox, Thunderbird, Epiphany: New releases fix vulnerabilities)


    Mozilla-based products are vulnerable to multiple security issues. Firstly
    routines handling the display of BMP images and VCards contain an integer
    overflow and a stack buffer overrun. Specific pages with long links, when
    sent using the "Send Page" function, and links with non-ASCII
    hostnames could both cause heap buffer overruns.
    Several issues were found and fixed in JavaScript rights handling:
    untrusted script code could read and write to the clipboard, signed scripts
    could build confusing grant privileges dialog boxes, and when dragged onto
    trusted frames or windows, JavaScript links could access information and
    rights of the target frame or window. Finally, Mozilla-based mail clients
    (Mozilla and Mozilla Thunderbird) are vulnerable to a heap overflow caused
    by invalid POP3 mail server responses.
  
Impact

    An attacker might be able to run arbitrary code with the rights of the user
    running the software by enticing the user to perform one of the following
    actions: view a specially-crafted BMP image or VCard, use the "Send
    Page" function on a malicious page, follow links with malicious
    hostnames, drag multiple JavaScript links in a row to another window, or
    connect to an untrusted POP3 mail server. An attacker could also use a
    malicious page with JavaScript to disclose clipboard contents or abuse
    previously-given privileges to request XPI installation privileges through
    a confusing dialog.
  
Workaround

    There is no known workaround covering all vulnerabilities.
  
References:
    http://www.mozilla.org/projects/security/known-vulnerabilities.html#mozilla1.7.3
    http://www.us-cert.gov/cas/techalerts/TA04-261A.html


Solution: 
    All users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv your-version
    # emerge your-version
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-26] Mozilla, Firefox, Thunderbird, Epiphany: New releases fix vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Mozilla, Firefox, Thunderbird, Epiphany: New releases fix vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/epiphany", unaffected: make_list("ge 1.2.9-r1"), vulnerable: make_list("lt 1.2.9-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-www/mozilla-firefox-bin", unaffected: make_list("ge 1.0_pre"), vulnerable: make_list("lt 1.0_pre")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 0.8"), vulnerable: make_list("lt 0.8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "mail-client/mozilla-thunderbird", unaffected: make_list("ge 0.8"), vulnerable: make_list("lt 0.8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-www/mozilla", unaffected: make_list("ge 1.7.3"), vulnerable: make_list("lt 1.7.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-www/mozilla-bin", unaffected: make_list("ge 1.7.3"), vulnerable: make_list("lt 1.7.3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-www/mozilla-firefox", unaffected: make_list("ge 1.0_pre"), vulnerable: make_list("lt 1.0_pre")
)) { security_warning(0); exit(0); }
