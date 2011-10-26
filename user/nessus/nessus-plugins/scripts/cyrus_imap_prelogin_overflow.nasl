#
# This script was written by Paul Johnston of Westpoint Ltd <paul@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11196);
 script_version ("$Revision: 1.2 $");
  
 name["english"] = "Cyrus IMAP pre-login buffer overrun";
 script_name(english:name["english"]);
 
 desc["english"] = "
According to its banner, the remote Cyrus IMAP 
server is vulnerable to a pre-login buffer overrun. 
 
An attacker without a valid login could exploit this, and would be 
able to execute arbitrary commands as the owner of the Cyrus 
process. This would allow full access to all users' mailboxes.

More information : http://online.securityfocus.com/archive/1/301864

Solution : If possible, upgrade to an unaffected version. However, at 
the time of writing no official fix was available. There is a source 
patch against 2.1.10 in the Bugtraq report.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for a pre-login buffer overrun in Cyrus IMAPd";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002 Paul Johnston, Westpoint Ltd");
 script_family(english:"Gain a shell remotely");

 script_dependencie("find_service.nes");	       		     
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");

 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/imap");
if(!port) port = 143;

key = string("imap/banner/", port);
banner = get_kb_item(key);
if(!banner)
{
  if(get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if(soc)
    { 
      banner = recv_line(socket:soc, length:255);
      close(soc);
    }
  }
}
if(!banner) exit(0);

if (("Cyrus IMAP4" >< banner) && egrep (pattern:"^\* OK.*Cyrus IMAP4 v([0-9]+\.[0-9]+\.[0-9]+.*) server ready", string:banner))
{
  version = ereg_replace(pattern:".* v(.*) server.*", string:banner, replace:"\1");
  set_kb_item (name:"imap/" + port + "/Cyrus", value:version);

  if(egrep(pattern:"^(1\.*|2\.0\.*|2\.1\.[1-9][^0-9]|2\.1\.10)[0-9]*$", string:version))
  {
    security_hole(port);
  }    
} 
