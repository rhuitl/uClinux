# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200507-03.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18607);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200507-03");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200507-03
(phpBB: Arbitrary command execution)


    Ron van Daal discovered that phpBB contains a vulnerability in the
    highlighting code.
  
Impact

    Successful exploitation would grant an attacker unrestricted
    access to the PHP exec() or system() functions, allowing the execution
    of arbitrary commands with the rights of the web server.
  
Workaround

    Please follow the instructions given in the phpBB announcement.
  
References:
    http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=302011


Solution: 
    The phpBB package is no longer supported by Gentoo Linux and has
    been removed from the Portage repository, no further announcements will
    be issued regarding phpBB updates. Users who wish to continue using
    phpBB are advised to monitor and refer to www.phpbb.com for more
    information.
    To continue using the Gentoo-provided phpBB
    package, please refer to the Portage documentation on unmasking
    packages and upgrade to 2.0.16.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200507-03] phpBB: Arbitrary command execution");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpBB: Arbitrary command execution');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apps/phpBB", unaffected: make_list("ge 2.0.16"), vulnerable: make_list("lt 2.0.16")
)) { security_hole(0); exit(0); }
