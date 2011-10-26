# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20953);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200602-11");
 script_cve_id("CVE-2006-0225");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200602-11
(OpenSSH, Dropbear: Insecure use of system() call)


    To copy from a local filesystem to another local filesystem, scp
    constructs a command line using \'cp\' which is then executed via
    system(). Josh Bressers discovered that special characters are not
    escaped by scp, but are simply passed to the shell.
  
Impact

    By tricking other users or applications to use scp on maliciously
    crafted filenames, a local attacker user can execute arbitrary commands
    with the rights of the user running scp.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0225


Solution: 
    All OpenSSH users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/openssh-4.2_p1-r1"
    All Dropbear users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/dropbear-0.47-r1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200602-11] OpenSSH, Dropbear: Insecure use of system() call");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenSSH, Dropbear: Insecure use of system() call');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/openssh", unaffected: make_list("ge 4.2_p1-r1"), vulnerable: make_list("lt 4.2_p1-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-misc/dropbear", unaffected: make_list("ge 0.47-r1"), vulnerable: make_list("lt 0.47-r1")
)) { security_warning(0); exit(0); }
