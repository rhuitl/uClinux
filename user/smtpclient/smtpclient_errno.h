/*   ____  __  __ _____ ____  
**  / ___||  \/  |_   _|  _ \ 
**  \___ \| |\/| | | | | |_) |
**   ___) | |  | | | | |  __/ 
**  |____/|_|  |_| |_| |_|    
**   
**  SMTP -- simple SMTP client
**
**  This program is a minimal SMTP client that takes an email
**  message body and passes it on to a SMTP server (default is the
**  MTA on the local host). Since it is completely self-supporting,
**  it is especially suitable for use in restricted environments.
**
**  ======================================================================
**
**  Copyright (c) 1997 Ralf S. Engelschall, All rights reserved.
**
**  This program is free software; it may be redistributed and/or modified
**  only under the terms of either the Artistic License or the GNU General
**  Public License, which may be found in the SMTP source distribution.
**  Look at the file COPYING. 
**
**  This program is distributed in the hope that it will be useful, but
**  WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  ======================================================================
**
**  smtp_errno.h -- errno support header
*/

extern char *errorstr(int errnum);

/*EOF*/
