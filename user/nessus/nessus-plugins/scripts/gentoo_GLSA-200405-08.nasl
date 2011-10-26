# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14494);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200405-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200405-08
(Pound format string vulnerability)


    A format string flaw in the processing of syslog messages was discovered
    and corrected in Pound.
  
Impact

    This flaw may allow remote execution of arbitrary code with the rights of
    the Pound daemon process. By default, Gentoo uses the "nobody" user to run
    the Pound daemon.
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of Pound.
  
References:
    http://www.apsis.ch/pound/pound_list/archive/2003/2003-12/1070234315000#1070234315000


Solution: 
    All users of Pound should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-www/pound-1.6"
    # emerge ">=net-www/pound-1.6"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200405-08] Pound format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pound format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/pound", unaffected: make_list("ge 1.6"), vulnerable: make_list("le 1.5")
)) { security_hole(0); exit(0); }
