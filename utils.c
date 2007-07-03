/*
 * Copyright (C) 2007, Sébastien Le Ray
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * utils.c : Some utility functions.
 */

#include "nss-sqlite.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <sqlite3.h>
#include <string.h>

/**
 * Open the database specified by NSS_SQLITE_DBFILE and prepare a statement.
 * @param ppDb A pointer to a struct sqlite3* which will be initialized.
 * @param ppSt A pointer to a struct sqlite3_stmt* which will be initialized
 *      using sql string containing in sql.
 * @param sql String containing SQL statement to prepare.
 */
int open_and_prepare(struct sqlite3** ppDb, struct sqlite3_stmt** ppSt, const char* sql) {
    if(sqlite3_open(NSS_SQLITE_DBFILE, ppDb) != SQLITE_OK) {
        NSS_ERROR(sqlite3_errmsg(*ppDb));
        sqlite3_close(*ppDb);
        return FALSE;
    }

    if(sqlite3_prepare(*ppDb, sql, strlen(sql), ppSt, NULL) != SQLITE_OK) {
        NSS_ERROR(sqlite3_errmsg(*ppDb));
        sqlite3_finalize(*ppSt);
        sqlite3_close(*ppDb);
        return FALSE;
    }
    return TRUE;
}

/*
 * Fetch a record from a statement and translate sqlite return code
 * into a directly usable nss_status code.
 * @param pDb Database handle, will be closed if something fails.
 * @param pSt Statement to fetch from, will be finalized if something
 *      goes wrong.
 */

enum nss_status fetch_first(struct sqlite3* pDb, struct sqlite3_stmt* pSt) {
    int res = sqlite3_step(pSt);
    switch(res) {
        /* Something was wrong with locks, try again later. */
        case SQLITE_BUSY:
            sqlite3_finalize(pSt);
            sqlite3_close(pDb);
        return NSS_STATUS_TRYAGAIN;
        /* No row returned (?) */
        case SQLITE_DONE:
            sqlite3_finalize(pSt);
            sqlite3_close(pDb);
        return NSS_STATUS_NOTFOUND;
        case SQLITE_ROW:
            return NSS_STATUS_SUCCESS;
        break;
        default:
            sqlite3_finalize(pSt);
            sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }
}

/*
 * Fill a group struct using given information.
 * @param pDb Handle to a database used to fetch group's members.
 * @param gbuf Struct which will be filled with various info.
 * @param buf Buffer which will contain all strings pointed to by
 *      gbuf.
 * @param buflen Buffer length.
 * @param name Groupname.
 * @param pw Group password.
 * @param gid Group ID.
 * @param errnop Pointer to errno, will be filled if something goes
 *      wrong.
 */

enum nss_status fill_group(struct sqlite3 *pDb, struct group *gbuf, char* buf, size_t buflen,
    const unsigned char *name, const unsigned char *pw, gid_t gid, int *errnop) {
    int name_length = strlen((char*)name) + 1;
    int pw_length = strlen((char*)pw) + 1;
    int total_length = name_length + pw_length;

    if(buflen < total_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    strcpy(buf, (const char*)name);
    gbuf->gr_name = buf;
    buf += name_length;
    strcpy(buf, (const char*)pw);
    gbuf->gr_passwd = buf;
    gbuf->gr_gid = gid;
    buf += pw_length;

    /* We have a group, we now need to fetch its users */
    get_users(pDb, gbuf->gr_gid, buf, buflen - total_length, errnop);
    gbuf->gr_mem = (char**)buf;

    return NSS_STATUS_SUCCESS;
}

/*
 * Fill an user struct using given information.
 * @param pwbuf Struct which will be filled with various info.
 * @param buf Buffer which will contain all strings pointed to by
 *      pwbuf.
 * @param buflen Buffer length.
 * @param name Username.
 * @param pw Group password.
 * @param uid User ID.
 * @param gid Main group ID.
 * @param gecos Extended information (real user name).
 * @param shell User's shell.
 * @param homedir User's home directory.
 * @param errnop Pointer to errno, will be filled if something goes
 *      wrong.
 */

enum nss_status fill_passwd(struct passwd* pwbuf, char* buf, size_t buflen,
    const char* name, const char* pw, uid_t uid, gid_t gid, const char* gecos,
    const char* shell, const char* homedir, int* errnop) {
    int name_length = strlen(name) + 1;
    int pw_length = strlen(pw) + 1;
    int gecos_length = strlen(gecos) + 1;
    int shell_length = strlen(shell) + 1;
    int homedir_length = strlen(homedir) + 1;
    int total_length = name_length + pw_length + gecos_length + shell_length + homedir_length;

    if(buflen < total_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    pwbuf->pw_uid = uid;
    pwbuf->pw_gid = gid;
    strcpy(buf, name);
    pwbuf->pw_name = buf;
    buf += name_length;
    strcpy(buf, pw);
    pwbuf->pw_passwd = buf;
    buf += pw_length;
    strcpy(buf, gecos);
    pwbuf->pw_gecos = buf;
    buf += gecos_length;
    strcpy(buf, shell);
    pwbuf->pw_shell = buf;
    buf += shell_length;
    strcpy(buf, homedir);
    pwbuf->pw_dir = buf;

    return NSS_STATUS_SUCCESS;
}

