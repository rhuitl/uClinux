/*
 * configfile.h
 *
 * Function to read pptpd config file.
 *
 * $Id: configfile.h,v 1.1.1.2 2007-07-05 23:25:55 gerg Exp $
 */

#ifndef _PPTPD_CONFIGFILE_H
#define _PPTPD_CONFIGFILE_H

int read_config_file(char *filename, char *keyword, char *value);

#endif	/* !_PPTPD_CONFIGFILE_H */
