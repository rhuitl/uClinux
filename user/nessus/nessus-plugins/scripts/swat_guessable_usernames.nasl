#
# This script was written by Renaud Deraison <deraison@nessus.com>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10590);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2000-0938");
 
 
 name["english"] = "SWAT allows user names to be obtained by brute force";
 name["francais"] = "SWAT allows the obtention of user names by brute force";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote SWAT server replies with different error codes when
it is issued a bad user name or a bad password.

An attacker may use this flaw to obtain the list of
user names of the remote host by a brute force attack.

As SWAT does not log login attempts, an attacker may use
this flaw even more effectively

Solution : get the latest version of samba, or disable swat
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Detect SWAT server port";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("swat_detect.nasl");
 script_require_ports("Services/swat");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/swat");
if(!port) exit(0);

if (get_port_state(port))
{
 soctcp901 = http_open_socket(port);

 if (soctcp901)
 {
  sendata = http_get(item:"/", port:port);
  sendata = sendata - string("\r\n\r\n");
  
  #
  # First attempt - we try to log in as nobodyhome123/a
  #
  
  sendata = sendata + string("\r\nAuthorization: Basic bm9zdWNodXNlcjEyMzQ6bm9wYXNz\r\n\r\n");
  
  send(socket:soctcp901, data:sendata);
  code1 = recv_line(socket:soctcp901, length:8196);
  http_close_socket(soctcp901);
  
  soctcp901 = http_open_socket(port);
  sendata = http_get(item:"/", port:port);
  sendata = sendata - string("\r\n\r\n");
  
  #
  # Second attempt - we try to log in as root:nopass
  #
 
  sendata = sendata + string("\r\nAuthorization: Basic cm9vdDpub3Bhc3MK\r\n\r\n");
  send(socket:soctcp901, data:sendata);
  code2   = recv_line(socket:soctcp901, length:8196);
  http_close_socket(soctcp901);

  if(("401" >< code1)  &&
     ("401" >< code2))
     {
       if(!(code1 == code2))security_warning(port);
      }
 }
}
