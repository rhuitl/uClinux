# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14571);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-15");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-15
(Tomcat: Insecure installation)


    The Gentoo ebuild for Tomcat sets the ownership of the Tomcat init scripts
    as tomcat:tomcat, but those scripts are executed with root privileges when
    the system is started. This may allow a member of the tomcat group to run
    arbitrary code with root privileges when the Tomcat init scripts are run.
  
Impact

    This could lead to a local privilege escalation or root compromise by
    authenticated users.
  
Workaround

    Users may change the ownership of /etc/init.d/tomcat* and
    /etc/conf.d/tomcat* to be root:root:
    # chown -R root:root /etc/init.d/tomcat*
    # chown -R root:root /etc/conf.d/tomcat*
  

Solution: 
    All Tomcat users can upgrade to the latest stable version, or simply apply
    the workaround:
    # emerge sync
    # emerge -pv ">=www-servers/tomcat-5.0.27-r3"
    # emerge ">=www-servers/tomcat-5.0.27-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-15] Tomcat: Insecure installation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Tomcat: Insecure installation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-servers/tomcat", unaffected: make_list("ge 5.0.27-r3", "rge 4.1.30-r4", "rge 3.3.2-r2"), vulnerable: make_list("lt 5.0.27-r3")
)) { security_warning(0); exit(0); }
