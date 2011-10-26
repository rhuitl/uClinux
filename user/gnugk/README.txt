                Using GNU Gatekeeper on a SecureComputing SG565
                -----------------------------------------------


Background
==========

This README details how to run a precompiled copy (ver 2.2.6) of GNU Gatekeeper 
(http://www.gnugk.org/) on a SecureComputing SnapGear SG565 networking 
appliance.

The precompiled version of GNU Gatekeeper has been tested with the most current
version of the SG565 firmware, SG565_v3.1.5_20070516.sgu. It may not work 
correctly with other versions of the SG565 firmware.


Setup
=====

The following instructions show how to setup the SG565 unit to run Gatekeeper
from a command prompt. It also gives details on how to setup a MySQL database
for authentication of users and recording connections for accounting purposes.
The SG565 should be connected and configured such that it can be accessed over 
the LAN using SSH/telnet and HTTP.

The instructions shown here should work with the supplied configuration file 
(gnugk.ini). They assume that MySQL server is already installed on a PC which 
is connected via the LAN to the SG565. If MySQL access is not required then the 
configuration file can be modified to remove MySQL support and the MySQL 
section below can be skipped.


Configuring MySQL server for Authentication and Accounting
----------------------------------------------------------

. From a command prompt on the PC that has MySQL installed, connect to the 
  MySQL server as root:

  $ mysql -u root -p <mysql password>

. Create a gk user with the password gkpassword that can connect from any host:

  mysql> GRANT ALL PRIVILEGES ON *.* TO 'gk'@'%' IDENTIFIED BY 'gkpassword' WITH 
         GRANT OPTION;

. Create a billing database:

  mysql> CREATE DATABASE billing;

. Use the billing database:

  mysql> USE billing;

. Create a customer table to hold user names and passwords:

  mysql> CREATE TABLE customer (username VARCHAR(20), password VARCHAR(20));

. Add some user information (this can be done in other ways): 

  mysql> INSERT INTO customer VALUES ('jan', 'jansecret');
  mysql> INSERT INTO customer VALUES ('joe', 'joesecret');

. Create calls table to keep track of calls:

  mysql> CREATE TABLE calls (sessid VARCHAR(25), callno VARCHAR(25), username 
         VARCHAR(25), calling VARCHAR(25), called VARCHAR(25), duration 
         VARCHAR(25), disconnectcause VARCHAR(25));

. Quit from MySQL:

  mysql> quit
  Bye

When GNU Gatekeeper starts, it will check the user name/passwords listed in the 
customer table for authenticating users. It will also log calls to the calls 
table.

Configuring the SG565
---------------------

. Using a Linux PC, extract the contents of the .tar.bz2 file onto a USB drive. 
  The USB drive should be formatted with the ext2 filesystem and have 
  approximately 16Mbytes free space. The files will extract into directory 
  called gk.

. Eject the USB drive from the PC and then plug the USB drive into a running 
  SG565 unit.

. Use the web interface to navigate to 'Web Cache' -> 'Storage' -> 
  'Local Storage'. On this page, click on the 'Device' drop down list and 
  select the USB device which should be called 'USB Mass Storage Device' or 
  something similar. Click Submit. This step is to ensure that the USB drive 
  is automatically mounted.
  
. If Gatekeeper is going to be used by devices connecting from the Internet 
  side of the SG565, i.e. not LAN devices, then a hole in the firewall must be 
  created so that Gatekeeper can talk to these devices. This can be done by 
  using the web interface, navigating to 'Packet Filtering' in the 'FIREWALL' 
  section and adding a 'Packet Filter Rule'. The rule should be set to 'Accept' 
  'Input' from 'Any Internet interface' on TCP port 1721 and UDP port 1719.

. SSH or telnet into the SG565 unit and log in as root to get a command prompt.

. Change directory to /var/mnt/xxxx/y/gk where xxxx is a long number which 
  changes depending on the type of the USB drive and y is the partition number 
  (usually 1).

. The configuration file needs to be modified so that the IP address of the 
  MySQL server is correct. This can be done by using vi to edit gnugk.ini and 
  changing the 192.168.0.1 addresses to the correct address for your MySQL 
  server.

. If a MySQL server is not being used, then the configuration file will need 
  to be modified to remove mention of the MySQL server for authentication 
  and accounting.

. Run the gnugk server by running:

  ./gnugk -c gnugk.ini

  The server will take 10 seconds or so to start and then should print 

  OpenH323 Gatekeeper - The GNU Gatekeeper with ID 'GnuGk' started
  Gatekeeper(GNU) Version(2.2.6) Ext(pthreads=1,radius=1,mysql=1,
  ......

  By default it will listen on all available network interfaces for incoming 
  connections.

