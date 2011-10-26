# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200402-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14446);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200402-02");
 script_cve_id("CVE-2004-0083");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200402-02
(XFree86 Font Information File Buffer Overflow)


    Exploitation of a buffer overflow in The XFree86 Window System
    discovered by iDefence allows local attackers to gain root
    privileges.
    The problem exists in the parsing of the \'font.alias\' file. The X
    server (running as root) fails to check the length of the user
    provided input, so a malicious user may craft a malformed
    \'font.alias\' file causing a buffer overflow upon parsing,
    eventually leading to the execution of arbitrary code.
    To reproduce the overflow on the command line one can run:
    # cat > fonts.dir <<EOF
    1
    word.bdf -misc-fixed-medium-r-semicondensed--13-120-75-75-c-60-iso8859-1
    EOF
    # perl -e \'print "0" x 1024 . "A" x 96 . "\\n"\' > fonts.alias
    # X :0 -fp $PWD
    {Some output removed}... Server aborting... Segmentation fault (core dumped)
  
Impact

    Successful exploitation can lead to a root compromise provided
    that the attacker is able to execute commands in the X11
    subsystem. This can be done either by having console access to the
    target or through a remote exploit against any X client program
    such as a web-browser, mail-reader or game.
  
Workaround

    No immediate workaround is available; a software upgrade is required.
    Gentoo has released XFree 4.2.1-r3, 4.3.0-r4 and 4.3.99.902-r1 and
    encourages all users to upgrade their XFree86
    installations. Vulnerable versions are no longer available in
    Portage.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0083
    http://www.idefense.com/application/poi/display?id=72&type=vulnerabilities


Solution: 
    All users are recommended to upgrade their XFree86 installation:
    # emerge sync
    # emerge -pv x11-base/xfree
    # emerge x11-base/xfree
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200402-02] XFree86 Font Information File Buffer Overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'XFree86 Font Information File Buffer Overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-base/xfree", unaffected: make_list("eq 4.2.1-r3", "eq 4.3.0-r4", "ge 4.3.99.902-r1"), vulnerable: make_list("lt 4.3.99.902-r1")
)) { security_hole(0); exit(0); }
