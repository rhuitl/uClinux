# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-29.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15581);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200410-29");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-29
(PuTTY: Pre-authentication buffer overflow)


    PuTTY fails to do proper bounds checking on SSH2_MSG_DEBUG packets. The
    "stringlen" parameter value is incorrectly checked due to signedness
    issues. Note that this vulnerability is similar to the one described in
    GLSA 200408-04 but not the same.
  
Impact

    When PuTTY connects to a server using the SSH2 protocol, an attacker may be
    able to send specially crafted packets to the client, resulting in the
    execution of arbitrary code with the permissions of the user running PuTTY.
    Note that this is possible during the authentication process but before
    host key verification.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.idefense.com/application/poi/display?id=155
    http://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html


Solution: 
    All PuTTY users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/putty-0.56"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-29] PuTTY: Pre-authentication buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PuTTY: Pre-authentication buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/putty", unaffected: make_list("ge 0.56"), vulnerable: make_list("le 0.55")
)) { security_warning(0); exit(0); }
