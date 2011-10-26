#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18261);
  script_version("$Revision: 1.4 $");

  name["english"] = "Linux Distribution Detection";
  script_name(english:name["english"]);
 
  desc["english"] = "
This script extracts the banner of the remote web server and attempts to 
determine which exact Linux distribution the remote host is running.

Solution : If you do not wish to display this information, edit httpd.conf and 
set the directive 'ServerTokens Prod' and restart Apache.

Risk factor : None";
  script_description(english:desc["english"]);
 
  summary["english"] = "Guesses the remote distribution version";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "General";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include('http_func.inc');
include('http_keepalive.inc');



#-----------------------------------------------------------#
# Mandrake                                                  #
#-----------------------------------------------------------#

i = 0; j = 0;
sig[i++]	= "Apache/1.3.6 (Unix) (Mandrake/Linux)";
name[j++]	= "Mandrake Linux 6.0";

sig[i++]	= "Apache/1.3.9 (Unix) (NetRevolution Advanced Server/Linux-Mandrake)";
name[j++]	= "Mandrake Linux 6.1 or 7.0";


sig[i++]	= "Apache-AdvancedExtranetServer/1.3.12 (NetRevolution/Linux-Mandrake)";
name[j++]	= "Mandrake Linux 7.1";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.14 (Linux-Mandrake/";
name[j++]	= "Mandrake Linux 7.2";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.19 (Linux-Mandrake/";
name[j++]	= "Mandrake Linux 8.0";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.20 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 8.1";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.22 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 7.1, 7.2, 8.0 or 8.1";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 8.2";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 9.0";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.27 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 9.1";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.44 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 9.1";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.28 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 9.2";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.47 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 9.1 or 9.2";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.29 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 10.0";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.48 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 10.0";

sig[i++]	= "Apache-AdvancedExtranetServer/1.3.31 (Linux-Mandrake/";
name[j++]	= "Mandrake Linux 10.1";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.50 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 10.0"; # patched

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.50 (Mandrake Linux/";
name[j++]	= "Mandrake Linux 10.1";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.53 (Mandriva Linux/";
name[j++]	= "Mandriva Linux 2005";

sig[i++]	= "Apache-AdvancedExtranetServer/2.0.54 (Mandriva Linux/";
name[j++]	= "Mandriva Linux 2006";

#-----------------------------------------------------------#
# Red Hat                                                   #
#-----------------------------------------------------------#

sig[i++] 	= "Apache/1.2.6 Red Hat";
name[j++]	= "Red Hat Linux 5.1";

sig[i++] 	= "Apache/1.3.3 (Unix) (Red Hat/Linux)";
name[j++]	= "Red Hat Linux 5.2";

sig[i++] 	= "Apache/1.3.6 (Unix) (Red Hat/Linux)";
name[j++]	= "Red Hat Linux 6.0";

sig[i++] 	= "Apache/1.3.9 (Unix) (Red Hat/Linux)";
name[j++]	= "Red Hat Linux 6.1";

sig[i++] 	= "Apache/1.3.12 (Unix) (Red Hat/Linux)";
name[j++]	= "Red Hat Linux 6.2 or 7.0";

sig[i++] 	= "Apache/1.3.19 (Unix) (Red-Hat/Linux)";
name[j++]	= "Red Hat Linux 7.1";

sig[i++] 	= "Apache/1.3.20 (Unix) (Red-Hat/Linux)";
name[j++]	= "Red Hat Linux 7.2";

sig[i++] 	= "Apache/1.3.23 (Unix) (Red-Hat/Linux)";
name[j++]	= "Red Hat Linux 7.3";

sig[i++]	= "Apache/2.0.40 (Red Hat Linux)";
name[j++]	= "Red Hat Linux 8.0 or 9";

sig[i++] 	= "Apache/1.3.22 (Unix)  (Red-Hat/Linux)";
name[j++]	= "Red Hat Enterprise Linux 2.1";

sig[i++]  	= "Apache/1.3.27 (Unix)  (Red-Hat/Linux)";
name[j++] 	= "Red Hat Enterprise Linux 2.1";

sig[i++]  	= "Apache/2.0.46 (Red Hat)";
name[j++] 	= "Red Hat Enterprise Linux 3";

sig[i++]  	= "Apache/2.0.52 (Red Hat)";
name[j++] 	= "Red Hat Enterprise Linux 4";


#-----------------------------------------------------------#
# SuSE                                                      #
#-----------------------------------------------------------#

sig[i++]	= "Apache/1.3.6 (Unix) (SuSE/Linux)";
name[j++]	= "SuSE Linux 6.1";

sig[i++]	= "Apache/1.3.9 (Unix) (SuSE/Linux)";
name[j++]	= "SuSE Linux 6.2";

sig[i++]	= "Apache/1.3.12 (Unix) (SuSE/Linux)";
name[j++]	= "SuSE Linux 6.4 or SuSE Linux 7.0";

sig[i++]	= "Apache/1.3.17 (Unix) (SuSE/Linux)";
name[j++]	= "SuSE Linux 7.1";

sig[i++]	= "Apache/1.3.19 (Unix) (SuSE/Linux)";
name[j++]	= "SuSE Linux 7.2";

sig[i++]	= "Apache/1.3.20 (Linux/SuSE)";
name[j++]	= "SuSE Linux 7.3";

sig[i++]	= "Apache/1.3.23 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.0";

sig[i++]	= "Apache/1.3.26 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.1";

sig[i++]	= "Apache/1.3.27 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.2";

sig[i++]	= "Apache/1.3.28 (Linux/SuSE)";
name[j++]	= "SuSE Linux 9.0";


sig[i++]	= "Apache/2.0.40 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.1";

sig[i++]	= "Apache/2.0.44 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.2";

sig[i++]	= "Apache/2.0.47 (Linux/SuSE)";
name[j++]	= "SuSE Linux 9.0";

sig[i++] 	= "Apache/2.0.48 (Linux/SuSE)";
name[j++]	= "SuSE Linux 8.1, 8.2 or 9.0";

sig[i++] 	= "Apache/2.0.49 (Linux/SuSE)"; 
name[j++]	= "SuSE Linux 9.1";

sig[i++] 	= "Apache/2.0.50 (Linux/SUSE)";
name[j++]	= "SuSE Linux 9.2";

sig[i++] 	= "Apache/2.0.53 (Linux/SUSE)";
name[j++]	= "SuSE Linux 9.3";

sig[i++] 	= "Apache/2.0.54 (Linux/SUSE)";
name[j++]	= "SuSE Linux 10.0";

#-----------------------------------------------------------#
# Fedora                                                    #
#-----------------------------------------------------------#

sig[i++] 	= "Apache/2.0.47 (Fedora)";
name[j++]	= "Fedora Core 1";

sig[i++] 	= "Apache/2.0.48 (Fedora)"; # patched
name[j++]	= "Fedora Core 1";

sig[i++] 	= "Apache/2.0.49 (Fedora)";
name[j++]	= "Fedora Core 1 or Core 2";

sig[i++] 	= "Apache/2.0.50 (Fedora)";
name[j++]	= "Fedora Core 1 or Core 2";

sig[i++] 	= "Apache/2.0.51 (Fedora)";
name[j++]	= "Fedora Core 2";

sig[i++] 	= "Apache/2.0.52 (Fedora)";
name[j++]	= "Fedora Core 3";

sig[i++] 	= "Apache/2.0.54 (Fedora)";
name[j++]	= "Fedora Core 4";

sig[i++] 	= "Apache/2.2.0 (Fedora)";
name[j++]	= "Fedora Core 5";

#-----------------------------------------------------------#
# Debian                                                    #
#-----------------------------------------------------------#

sig[i++]	= "Apache/1.0.5 (Unix) Debian/GNU";
name[j++]	= "Debian 1.1 (buzz)";

sig[i++]	= "Apache/1.1.1 (Unix) Debian/GNU";
name[j++]	= "Debian 1.2 (rex)";

sig[i++]	= "Apache/1.1.3 (Unix) Debian/GNU";
name[j++]	= "Debian 1.3 (bo)";

sig[i++]	= "Apache/1.3.0 (Unix) Debian/GNU";
name[j++]	= "Debian 2.0 (hamm)";

sig[i++]	= "Apache/1.3.3 (Unix) Debian/GNU";
name[j++]	= "Debian 2.1 (slink)";

sig[i++]	= "Apache/1.3.9 (Unix) Debian/GNU";
name[j++]	= "Debian 2.2 (potato)";

sig[i++]	= "Apache/1.3.26 (Unix) Debian GNU/Linux";
name[j++]	= "Debian 3.0 (woody)";

sig[i++]	= "Apache/1.3.33 (Unix) Debian GNU/Linux";
name[j++]	= "Debian 3.1 (sarge)";

sig[i++]	= "Apache/2.0.54 (Unix) Debian GNU/Linux";
name[j++]	= "Debian 3.1 (sarge)";

sig[i++]	= "Apache/1.3.33 (Unix) Debian GNU/Linux";
name[j++]	= "Debian unstable (sid)";

sig[i++]	= "Apache/2.0.55 (Unix) Debian GNU/Linux";
name[j++]	= "Debian unstable (sid)";

ports = get_kb_list("Services/www");
if ( isnull(ports) ) ports = make_list(80);
else ports = make_list(ports);


foreach port ( ports )
{
 banner = get_http_banner(port:port);
 if ( banner )
 {
 match = NULL;
 num_matches = 0;
 for ( i = 0 ; sig[i] ; i ++ )
 {
   if ( sig[i] >< banner )
 	{
 	 if ( num_matches > 0 ) match += '\n';
	 match += ' - ' + name[i];
	 num_matches ++;
	} 
 }

  if ( num_matches > 0  )
  {
  security_note(port:0, 
data:"Using the remote HTTP banner, it is possible to guess that the 
Linux distribution installed on the remote host is :
" + match);
  if ( match == 1 ) set_kb_item(name:"Host/Linux/Distribution", value:match);
 exit(0);
  }
 } 


}
 
