#
#  (C) Tenable Network Security
#

if ( NASL_LEVEL < 3000 ) exit(0);

 desc = "
Synopsis :

It is possible to enumerate installed software on the remote host, via SSH.

Description :

This plugin lists the software installed on the remote host by calling the
appropriate command (rpm -qa on RPM-based Linux distributions, etc...)

Solution :

Remove software that is not compliant with your company policy.

Risk factor : 

None";


if (description) {
  script_id(22869);
  script_version("$Revision: 1.1 $");

  script_name(english:"Software Enumeration (via SSH)");
  script_summary(english:"Displays the list of packages installed on the remote software"); 
 
  script_description(english:desc);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("ssh_get_info.nasl");

  exit(0);
}


function report(os, buf)
{
 report = desc + '\nPlugin output:\n\nHere is the list of packages installed on the remote ' + os + ' system : \n' + buf;
 security_note(port:0, data:report);
 exit(0);
}

list = make_array("Host/FreeBSD/pkg_info", "FreeBSD",
		  "Host/RedHat/rpm-list",  "Red Hat Linux",
		  "Host/CentOS/rpm-list",  "CentOS Linux",
		  "Host/Mandrake/rpm-list",  "Mandriva Linux",
		  "Host/SuSE/rpm-list",  "SuSE Linux",
		  "Host/SuSE/rpm-list",  "SuSE Linux",
		  "Host/Gentoo/qpkg-list",  "Gentoo Linux",
		  "Host/Debian/dpkg-l",    "Linux",
		  "Host/Slackware/packages", "Slackware Linux",
		  "Host/MacOSX/packages",   "Mac OS X",
		  "Host/Solaris/showrev",   "Solaris",
		  "Host/AIX/lslpp",	    "AIX",
		  "Host/HP-UX/swlist",      "HP-UX");


foreach item ( keys(list) ) 
{
 buf = get_kb_item(item);
 if ( buf ) report(os:list[item], buf:buf);
}

