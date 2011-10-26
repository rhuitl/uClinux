#
# (C) Tenable Network Security
#

 desc["english"] = "
Synopsis :

It is possible to log into the remote switch using one
of its default accounts.

Description :

It is possible to log into the remote Nortel Accelar routing
switch by using one of the following login and password
combination :

	- l2/l2
	- l3/l3
	- ro/ro
	- rw/rw
	- rwa/rwa


An attacker may use these credentials to gain access to the remote
host.


Solution :

Set a strong password for these accounts

Risk factor :

High / CVSS Base Score : 9 
(AV:R/AC:L/Au:NR/C:P/A:C/I:C/B:N)";

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15715);
 script_version("$Revision: 1.7 $");
 script_name(english:"Nortel Default Accounts");
	     


 script_description(english:desc["english"]);
 
 script_summary(english:"Logs into the remote switch with a default login/password pair");

 script_category(ACT_GATHER_INFO);

 script_family(english:"Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_require_keys("Settings/Thorough");
 exit(0);
}

#
# The script code starts here : 
#
include("ssh_func.inc");
include("global_settings.inc");

if ( ! thorough_tests ) exit(0);


credentials = make_array("12", "12",
			 "13", "13",
			 "ro", "ro",
			 "rw", "rw",
			 "rwa", "rwa");



port = kb_ssh_transport();
if ( ! port || !get_port_state(port) ) exit(0);
if ( ! get_kb_item("SSH/banner/" + port) ) exit(0);

foreach key ( keys(credentials) )
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);
 ret = ssh_login(socket:soc, login:key, password:credentials[key]);
 close(soc);
 if ( ret == 0 ) working_login += key + '/' + credentials[key] + '\n';
		
}

if ( working_login )
{
 report = desc["english"] + '\n\nPlugin output :\n\nThe following accounts have been tested with success:\n' + working_login;
 security_hole(port:port, data:report); 
}
