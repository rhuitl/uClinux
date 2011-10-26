#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14657);
 script_version ("$Revision: 1.7 $");
 name["english"] = "RedHat update level";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin makes sure the remote RedHat server is running
the latest bugfix update package.

Solution : http://www.redhat.com/security/notes/ 
Risk Factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for RedHat update level"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/release");
 exit(0);
}


#the code

#here the list of redhat version/last update level

lastupdate[2]=7;
lastupdate[3]=7;
lastupdate[4]=2;

buf=get_kb_item("Host/RedHat/release");
if (!buf) exit(0);
v = eregmatch(string: buf, pattern: "Update ([0-9]+)");
if (isnull(v)) exit(0);
updatelevel=int(v[1]);

release=NULL;
if(egrep(pattern:"Red Hat Enterprise Linux.*release 3", string:buf) ) release=3;
else if (egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 2\.1", string:buf) ) release=2; 
else if (egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 4", string:buf) ) release=4;

if (isnull(release)) exit(0);

if (updatelevel < lastupdate[release])
{
str="The remote host is missing a RedHat update package.
Maintenance level "+updatelevel+" is installed, last is "+lastupdate[release]+".

You should install this package for your system to be up-to-date.

Solution : http://www.redhat.com/security/notes/ 
Risk Factor : High"; 
 security_hole(port:port, data:str);
 exit(0);
}
