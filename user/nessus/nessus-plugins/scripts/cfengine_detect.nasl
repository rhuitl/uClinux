# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# GPL
#

if(description)
{
 script_id(14315);
 script_version ("$Revision: 1.3 $");
 name["english"] = "cfengine detection and local identification";
 script_name(english:name["english"]);
 
 desc["english"] = "
The cfengine service is running on this port.  

Cfengine is a language-based system for testing and configuring
Unix and Windows systems attached to a TCP/IP network.

Risk factor : None";

 script_description(english:desc["english"]);
 
 summary["english"] = "check for the presence of cfengine with local identification version checks if possible";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "General";
 family["francais"] = "General";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(5308);

 if ( defined_func("bn_random") ) script_dependencies("ssh_get_info.nasl");
 exit(0);
}


port = 5308;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);


ver = get_kb_item("cfengine/version");
if ( ! ver ) exit(0);


set_kb_item(name:"cfengine/running", value:TRUE);

report = "
cfengine version "+ver+" is running on this port.
cfengine is a language-based system for testing and configuring 
unix and windows systems attached to a TCP/IP network.

Risk factor : None";

security_note(port:port, data:report);
