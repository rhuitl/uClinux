#
# This script was written by H D Moore
# 


if(description)
{
    script_id(10990);
    script_version ("$Revision: 1.13 $"); 
    # script_cve_id("CVE-MAP-NOMATCH");
    # NOTE: reviewed, and no CVE id currently assigned (jfs, december 2003)
    name["english"] = "FTP Service Allows Any Username";
    name["francais"] = "FTP Service Allows Any Username";
    script_name(english:name["english"], francais:name["francais"]);


    desc = "
The FTP service can be accessed using any username and password.
Many other plugins may trigger falsely because of this, so 
Nessus enable some countermeasures.

** If you find a useless warning on this port, please inform
** the Nessus team so that we fix the plugins.
 
Solution: None

Risk factor : None
";

    script_description(english: desc);
    script_summary(english: "FTP Service Allows Any Username");
    script_category(ACT_GATHER_INFO);
    script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Inc.",
               francais:"Ce script est Copyright (C) 2002 Digital Defense Inc.");

    script_family(english: "FTP");
    script_dependencie("ftpserver_detect_type_nd_version.nasl"); 
    exit(0);
}


#
# The script code starts here
#
include('global_settings.inc');
include('ftp_func.inc');
include('misc_func.inc');

port = get_kb_item("Services/ftp");
if (!port)port = 21;
if (! get_port_state(port)) exit(0);

n_cnx = 0; n_log = 0;

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);


for (i = 0; i < 4; i ++)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   n_cnx ++;
   u = rand_str(); p = rand_str();
   if (ftp_authenticate(socket:soc, user: u, pass: p))
     n_log ++;
   else
     exit(0);
   ftp_close(socket: soc);
 }
 else
  sleep(1);
}

debug_print('n_log=', n_log, '/ n_cnx=', n_cnx, '\n');

if (n_cnx > 1 && n_log > 0 )	# >= n_cnx ?
{
 set_kb_item(name:"ftp/" + port + "/AnyUser", value:TRUE);
 if (report_verbosity > 1) security_note(port:port);
} 
