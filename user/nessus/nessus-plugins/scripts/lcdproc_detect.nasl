#
# (C) Tenable Network Security
#

 
 desc["english"] = "
Synopsis :

A LCDproc server is listening on the remote host.

Description :

LCDproc is a client/server suite which contains drivers for
LCD devices.

The remote service can be used to display messages on the LCD
display attached to the remote host.

Solution : 

If you do not use the client-server abilities of this service,
filter incoming traffic to this port or configure the remote daemon
to not listen on the network interface.

See also : 

http://lcdproc.omnipotent.net/

Risk factor :

None";

if(description)
{
 script_id(10379);
 script_version ("$Revision: 1.6 $");
 name["english"] = "LCDproc Detection";
 script_name(english:name["english"]);


 script_description(english:desc["english"]);
 
 summary["english"] = "Detects the LCDproc service";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security"); 
 script_family(english:"Service detection");
 script_dependencie("find_service.nes");
  script_require_ports("Services/lcdproc", 13666);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/lcdproc");
if( ! port )port = 13666;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:'hello\r\n');
r = recv_line(socket:soc, length:4096);
if ( ! r ) exit(0);
r = chomp(r);

if ( r =~ "LCDproc [0-9.]* " )
 {
  version = ereg_replace(pattern:".*LCDproc ([0-9.]*) .*", string:r, replace:"\1");
  report = desc["english"] + '\n\nPlugin output :\n\nLCDproc version : ' + version;
  security_note(port:port, data:report);
  set_kb_item(name:"lcdproc/version", value:version);
 }
