#
# This script was written by Scott Adkins <sadkins@cns.ohiou.edu>
#
# See the Nessus Scripts License for details
#

if (description)
{
 script_id(10132);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-1999-0660");
 name["english"] = "Kuang2 the Virus";
 name["francais"] = "Kuang2 le Virus";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
 Kuang2 the Virus was found.

 Kuang2 the Virus is a program that infects all
 the executables on the system, as well as set up
 a server that allows the remote control of the
 computer.  The client program allows files to be
 browsed, uploaded, downloaded, hidden, etc on the
 infected machine.  The client program also  can
 execute programs on the remote machine.

 Kuang2 the Virus also has plugins that can be used
 that allows the client to do things to the remote
 machine, such as hide the icons and start menu, 
 invert the desktop, pop up message windows, etc.

 More Information:
 http://vil.mcafee.com/dispVirus.asp?virus_k=10213
 
 Solution: 
 Disinfect the computer with the latest copy of
 virus scanning software.  Alternatively, you can
 find a copy of the virus itself on the net by 
 doing an Altavista search.  The virus comes with
 the server, client and infector programs.  The
 client program not only allows you to remotely
 control infected machines, but disinfect the 
 machine the client is running on.

 Risk factor : High";


 desc["francais"] = "
 Kuang2 le virus a été trouvé.

 Kuang2 le virus est un programme qui infecte tous
 les executables sur le système, aussi bien que 
 l'installation par serveur qui laisse permet la 
 télécommande de l'ordinateur. Le programme de 
 client permet à des fichiers d'être parcourus, 
 téléchargement, téléchargé, caché, etc.. sur la 
 machine infectée. Le programme de client peut 
 également exécuter des programmes sur la machine
 à distance. 

 Kuang2 le virus a également les plugins qui 
 peuvent être utilisés qui permet au client de 
 faire des choses à la machine à distance, telle 
 que la peau les graphismes et le menu de début, 
 inversent l'appareil de bureau, sautent vers le 
 haut des Windows de message, etc.

 Plus D'Information:
 http://vil.mcafee.com/dispVirus.asp?virus_k=10213

 Solution: 
 Désinfectez l'ordinateur avec la dernière copie 
 du logiciel de lecture de virus. Alternativement, 
 vous pouvez trouver une copie du virus elle-même 
 sur le filet en faisant une recherche d'Altavista. 
 Le virus vient avec les programmes de serveur, de 
 client et d'infector. Le programme de client vous 
 permet non seulement de contrôler à distance les 
 machines infectées, mais désinfecte la machine que 
 le client exécute en fonction. 

 Facteur de risque : Elevé.";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for Kuang2 the Virus";
 summary["francais"] = "Contrôles pour Kuang2 le Virus";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000 Scott Adkins",
		  francais:"Ce script est Copyright (C) 2000 Scott Adkins");

 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);

 script_dependencie("find_service.nes");
 script_require_ports(17300);

 exit(0);
}

#
# The script code starts here
#

port = 17300;
if (get_port_state(port))
{
    soc = open_sock_tcp(port);
    if (soc) {
	data = recv_line(socket:soc, length:100);
	if(!data)exit(0);
	if ("YOK2" >< data) security_hole(port);
        close(soc);
    }
}
