# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-30.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(17233);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200502-30");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-30
(cmd5checkpw: Local password leak vulnerability)


    Florian Westphal discovered that cmd5checkpw is installed setuid
    cmd5checkpw but does not drop privileges before calling execvp(), so
    the invoked program retains the cmd5checkpw euid.
  
Impact

    Local users that know at least one valid /etc/poppasswd
    user/password combination can read the /etc/poppasswd file.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All cmd5checkpw users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/cmd5checkpw-0.22-r2"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-30] cmd5checkpw: Local password leak vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cmd5checkpw: Local password leak vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/cmd5checkpw", unaffected: make_list("ge 0.22-r2"), vulnerable: make_list("le 0.22-r1")
)) { security_warning(0); exit(0); }
