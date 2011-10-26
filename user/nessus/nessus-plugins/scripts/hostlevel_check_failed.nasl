#
# (C) Tenable Network Security
# 

 desc["english"] = "
Synopsis :

It was not possible to log into the remote host

Description :

The credentials provided for the scan did not allow us to log into the
remote host.


Risk factor : 

None";

if(description)
{
 script_id(21745);
 script_version ("$Revision: 1.1 $");
 name["english"] = "Local Checks Failed";
 script_name(english:name["english"]);
 


 script_description(english:desc["english"]);
 
 summary["english"] = "Displays information about the scan";
 script_summary(english:summary["english"]);
 
 script_category(ACT_END);
 
 
 script_copyright(english:"This script is (C) 2006 Tenable Network Security, Inc.");
 family["english"] = "General";
 script_family(english:family["english"]);
 # No dependencies, since this is an ACT_END plugin
 exit(0);
}


include("smb_func.inc");
global_var report;


function check_svc(svc, port_name, default)
{
 local_var port, soc;
 
 if ( get_kb_item("HostLevelChecks/" + svc + "/failed") )
 {
  if ( !isnull(port_name) )
	port = get_kb_item(port_name);

  if ( ! port ) port = default;
  if ( get_port_state(port) )
  {
   soc = open_sock_tcp(port);
   if ( soc )
	{
         close(soc);
 	 report += '- It was not possible to log into the remote host via ' + svc + '\n';
	}
  }
 }
}


if ( ( str = get_kb_item("HostLevelChecks/failure") )  )
{
  report += 'The local checks failed because ' + str;
}

if ( get_kb_item("Host/local_checks_enabled") && ! report ) exit(0);

check_svc(svc:"ssh", default:22);
check_svc(svc:"telnet", port_name:"Services/telnet", default:23);
check_svc(svc:"rexec", port_name:"Services/rexec", default:513);
check_svc(svc:"rlogin", port_name:"Services/rlogin", default:513);
check_svc(svc:"rsh", port_name:"Services/rsh", default:514);


smb = get_kb_item("Host/OS/smb");

if ( smb && "Windows" >< smb )
 check_svc(svc:"smb", default:kb_smb_transport());




if ( report )
{
 report = desc["english"] + '\n\nPlugin output : \n\n' + report;
 security_note(port:0, data:report);
}
