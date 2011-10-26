#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14611);
 script_version ("$Revision: 1.8 $");
 name["english"] = "AIX maintenance level";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin makes sure the remote AIX server is running
the newest maintenance package.

Solution : http://www-912.ibm.com/eserver/support/fixes/ 
Risk Factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for maintenance level patch"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "AIX Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/AIX/oslevel");
 exit(0);
}


#the code

#here the list of last maintenance level
level4330=11;
level5100=8;
level5200=7;
level5300=3;

buf=get_kb_item("Host/AIX/oslevel");
if (!buf) exit(0);

 v=split(buf, sep:"-",keep: 0);
 if (isnull(v)) exit(0);
 osversion=int(v[0]);
 level=int(chomp(v[1]));

if (osversion==4330 && level < level4330)
{
str="The remote host is missing an AIX maintenance package.
Maintenance level "+level+" is installed, last is "+level4330+".

You should install this patch for your system to be up-to-date.

Solution : http://www-912.ibm.com/eserver/support/fixes/
Risk Factor : High"; 
 security_note(port:port, data:str);
  exit(0);
}

if (osversion==5100 && level < level5100)
{
str="The remote host is missing an AIX maintenance package.
Maintenance level "+level+" is installed, last is "+level5100+".

You should install this patch for your system to be up-to-date.

Solution : http://www-912.ibm.com/eserver/support/fixes/
Risk Factor : High"; 
 security_note(port:port, data:str);
  exit(0);
}

if (osversion==5200 && level < level5200)
{
str="The remote host is missing an AIX maintenance package.
Maintenance level "+level+" is installed, last is "+level5200+".

You should install this patch for your system to be up-to-date.

Solution : http://www-912.ibm.com/eserver/support/fixes/
Risk Factor : High"; 
 security_note(port:port, data:str);
  exit(0);
}

if (osversion==5300 && level < level5300)
{
str="The remote host is missing an AIX maintenance package.
Maintenance level "+level+" is installed, last is "+level5300+".

You should install this patch for your system to be up-to-date.

Solution : http://www-912.ibm.com/eserver/support/fixes/
Risk Factor : High"; 
 security_note(port:port, data:str);
  exit(0);
}
