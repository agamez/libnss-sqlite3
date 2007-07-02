#ifndef NSS_SQLITE_H
#define NSS_SQLITE_H

#define _GNU_SOURCE

#include <nss.h>
#include <syslog.h>
#include <stdio.h>

/* Some syslog shortcuts */
#ifdef DEBUG
#define NSS_DEBUG(msg, ...) syslog(LOG_DEBUG, (msg), ## __VA_ARGS__)
#else
#define NSS_DEBUG(msg, ...)
#endif

#define NSS_ERROR(msg, ...) syslog(LOG_ERR, (msg), ## __VA_ARGS__)

#define FALSE 0
#define TRUE !FALSE


/* FIXME move in a configuration file */
#define DBFILE "/var/db/auth.sqlite"
#endif
