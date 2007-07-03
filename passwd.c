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
 * passwd.c : Functions handling passwd entries retrieval.
 */

#include "nss-sqlite.h"
#include "utils.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <unistd.h>

/**
 * Setup everything needed to retrieve passwd entries.
 */
enum nss_status _nss_sqlite_setpwent(void) {
    NSS_DEBUG("Initializing pw functions\n");
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_sqlite_endpwent(void) {
    NSS_DEBUG("Finishing pw functions\n");
    return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_sqlite_getpwent_r(struct passwd *pwbuf, char *buf,
                      size_t buflen, int *errnop) {
    NSS_DEBUG("Getting next pw entry\n");
    return NSS_STATUS_UNAVAIL;
}

/**
 * Get user info by username.
 * Open database connection, fetch the user by name, close the connection.
 */

enum nss_status _nss_sqlite_getpwnam_r(const char* name, struct passwd *pwbuf,
               char *buf, size_t buflen, int *errnop) {
    sqlite3 *pDb;
    struct sqlite3_stmt* pSt;
    int res;
    uid_t uid;
    gid_t gid;
    const char* sql = "SELECT uid, gid, shell, homedir FROM shadow WHERE username = ?";
    const char* shell;
    const char* homedir;

    NSS_DEBUG("getpwnam_r: Looking for user %s\n", name);

    if(!open_and_prepare(&pDb, &pSt, sql)) {
        return NSS_STATUS_UNAVAIL;
    }

    if(sqlite3_bind_text(pSt, 1, name, -1, SQLITE_STATIC) != SQLITE_OK) {
        NSS_DEBUG(sqlite3_errmsg(pDb));
        sqlite3_finalize(pSt);
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }

    res = fetch_first(pDb, pSt);
    if(res != NSS_STATUS_SUCCESS) {
        return res;
    }

    /* SQLITE_ROW was returned, fetch data */
    uid = sqlite3_column_int(pSt, 0);
    gid = sqlite3_column_int(pSt, 1);
    shell = sqlite3_column_text(pSt, 2);
    homedir = sqlite3_column_text(pSt, 3);
    sqlite3_finalize(pSt);
    sqlite3_close(pDb);

    res = fill_passwd(pwbuf, buf, buflen, name, "x", uid, gid, "", shell, homedir, errnop);
    NSS_DEBUG("Look successfull !\n");
    return res;
}


enum nss_status _nss_sqlite_getpwuid_r(uid_t uid, struct passwd *pwbuf,
               char *buf, size_t buflen, int *errnop) {
    sqlite3 *pDb;
    struct sqlite3_stmt* pSt;
    int res;
    gid_t gid;
    const unsigned char *name;
    const unsigned char *shell;
    const unsigned char *homedir;
    const char *sql = "SELECT username, gid, shell, homedir FROM shadow WHERE uid = ?";

    NSS_DEBUG("getpwuid_r: looking for user #%d\n", uid);

    if(!open_and_prepare(&pDb, &pSt, sql)) {
        return NSS_STATUS_UNAVAIL;
    }

    if(sqlite3_bind_int(pSt, 1, uid) != SQLITE_OK) {
        NSS_DEBUG(sqlite3_errmsg(pDb));
        sqlite3_finalize(pSt);
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }

    res = sqlite3_step(pSt);

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
        break;
        default:
            sqlite3_finalize(pSt);
            sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }

    name = sqlite3_column_text(pSt, 0);
    gid = sqlite3_column_int(pSt, 1);
    shell = sqlite3_column_text(pSt, 2);
    homedir = sqlite3_column_text(pSt, 3);

    fill_passwd(pwbuf, buf, buflen, name, "*", uid, gid, "",
            shell, homedir, errnop);
   
    sqlite3_finalize(pSt);
    sqlite3_close(pDb);

    return NSS_STATUS_SUCCESS;
}

