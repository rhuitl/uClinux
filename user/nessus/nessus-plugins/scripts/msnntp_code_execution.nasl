#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15465);
 script_bugtraq_id(11379);
 script_cve_id("CVE-2004-0574");
 script_version ("$Revision: 1.7 $");
 if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2004-A-0018");

 name["english"] = "MS NNTP Vulnerability (883935)";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Microsoft NNTP server which is
vulnerable to a buffer overflow issue.

An attacker may exploit this flaw to execute arbitrary commands on the remote
host with the privileges of the NNTP server process.

Solution : http://www.microsoft.com/technet/security/bulletin/MS04-036.mspx
Risk factor : High";


 script_description(english:desc["english"]);
		    
 
 summary["english"] = "Checks the remote NNTP daemon version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencie("nntpserver_detect.nasl");
 script_require_ports("Services/nntp", 119);
 exit(0);
}

#
# The script code starts here
#



port = get_kb_item("Services/nntp");
if(!port)port = 119;
if (! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
banner = recv_line(socket:soc, length:8192);
if ( ! banner ) exit(0);
close(soc);

if ( "200 NNTP Service" >< banner )
{
 version = egrep(string:banner, pattern:"^200 NNTP Service");
 version = ereg_replace(string:version, pattern:"^200 NNTP Service .* Version: (.*) ", replace:"\1");
 ver = split(version, sep:".", keep:0);
 if ( int(ver[0]) == 6 )
 {
  if ( int(ver[1]) == 0 && ( int(ver[2]) < 3790 || ( int(ver[2]) == 3790 && int(ver[3]) < 206 ) ) ) security_hole(port);
 }

 if ( int(ver[0]) == 5 )
 {
  if ( int(ver[1]) == 0 && ( int(ver[2]) < 2195 || ( int(ver[2]) == 2195 && int(ver[3]) < 6972 ) ) ) security_hole(port);
 }
}
