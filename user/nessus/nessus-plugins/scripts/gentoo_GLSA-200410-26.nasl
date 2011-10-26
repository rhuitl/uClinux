# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-26.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15568);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-26");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-26
(socat: Format string vulnerability)


    socat contains a syslog() based format string vulnerablility in the
    \'_msg()\' function of \'error.c\'. Exploitation of this bug is only possible
    when socat is run with the \'-ly\' option, causing it to log messages to
    syslog.
  
Impact

    Remote exploitation is possible when socat is used as a HTTP proxy client
    and connects to a malicious server. Local privilege escalation can be
    achieved when socat listens on a UNIX domain socket. Potential execution of
    arbitrary code with the privileges of the socat process is possible with
    both local and remote exploitations.
  
Workaround

    Disable logging to syslog by not using the \'-ly\' option when starting
    socat.
  
References:
    http://www.dest-unreach.org/socat/advisory/socat-adv-1.html


Solution: 
    All socat users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/socat-1.4.0.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-26] socat: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'socat: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/socat", unaffected: make_list("ge 1.4.0.3"), vulnerable: make_list("lt 1.4.0.3")
)) { security_warning(0); exit(0); }
