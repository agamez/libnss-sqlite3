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
#include <string.h>
#include <unistd.h>

/**
 * Setup everything needed to retrieve passwd entries.
 */
enum nss_status _nss_sqlite_setpwent(void) {
    NSS_DEBUG("Initializing pw functions\n");
    return NSS_STATUS_SUCCESS;
}

/*
 * Free getpwent resources.
 */
enum nss_status _nss_sqlite_endpwent(void) {
    NSS_DEBUG("Finishing pw functions\n");
    return NSS_STATUS_SUCCESS;
}

/*
 * Return next passwd entry.
 * Not implemeted yet.
 */

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
    struct sqlite3_stmt* pSquery;
    int res;
    uid_t uid;
    gid_t gid;
    char* query;
    const char* shell;
    const char* homedir;

    NSS_DEBUG("getpwnam_r: Looking for user %s\n", name);

    if(sqlite3_open(NSS_SQLITE_PASSWD_DB, &pDb) != SQLITE_OK) {
        NSS_ERROR(sqlite3_errmsg(pDb));
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }

    if(!(query = get_query(pDb, "getpwnam_r")) ) {
        NSS_ERROR(sqlite3_errmsg(pDb));
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }

    if(sqlite3_prepare(pDb, query, strlen(query), &pSquery, NULL) != SQLITE_OK) {
        NSS_ERROR(sqlite3_errmsg(pDb));
        free(query);
        sqlite3_finalize(pSquery);
        sqlite3_close(pDb);
        return FALSE;
    }

    if(sqlite3_bind_text(pSquery, 1, name, -1, SQLITE_STATIC) != SQLITE_OK) {
        NSS_DEBUG(sqlite3_errmsg(pDb));
        free(query);
        sqlite3_finalize(pSquery);
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }

    res = res2nss_status(sqlite3_step(pSquery), pDb, pSquery);
    if(res != NSS_STATUS_SUCCESS) {
        free(query);
        return res;
    }

    /* SQLITE_ROW was returned, fetch data */
    uid = sqlite3_column_int(pSquery, 0);
    gid = sqlite3_column_int(pSquery, 1);
    shell = sqlite3_column_text(pSquery, 2);
    homedir = sqlite3_column_text(pSquery, 3);
    res = fill_passwd(pwbuf, buf, buflen, name, "x", uid, gid, "", shell, homedir, errnop);

    free(query);
    sqlite3_finalize(pSquery);
    sqlite3_close(pDb);

    NSS_DEBUG("Look successfull !\n");
    return res;
}

/*
 * Get user by UID.
 */

enum nss_status _nss_sqlite_getpwuid_r(uid_t uid, struct passwd *pwbuf,
               char *buf, size_t buflen, int *errnop) {
    sqlite3 *pDb;
    struct sqlite3_stmt* pSquery;
    int res, nss_res;
    gid_t gid;
    const unsigned char *name;
    const unsigned char *shell;
    const unsigned char *homedir;
    char* query;

    NSS_DEBUG("getpwuid_r: looking for user #%d\n", uid);

    if(sqlite3_open(NSS_SQLITE_PASSWD_DB, &pDb) != SQLITE_OK) {
        NSS_ERROR(sqlite3_errmsg(pDb));
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }

    if(!(query = get_query(pDb, "getpwuid_r")) ) {
        NSS_ERROR(sqlite3_errmsg(pDb));
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }


    if(sqlite3_prepare(pDb, query, strlen(query), &pSquery, NULL) != SQLITE_OK) {
        NSS_ERROR(sqlite3_errmsg(pDb));
        free(query);
        sqlite3_finalize(pSquery);
        sqlite3_close(pDb);
        return FALSE;
    }

    if(sqlite3_bind_int(pSquery, 1, uid) != SQLITE_OK) {
        NSS_DEBUG(sqlite3_errmsg(pDb));
        free(query);
        sqlite3_finalize(pSquery);
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }


    res = sqlite3_step(pSquery);
    nss_res = res2nss_status(res, pDb, pSquery);
    if(nss_res != NSS_STATUS_SUCCESS) {
        free(query);
        return nss_res;
    }


    name = sqlite3_column_text(pSquery, 0);
    gid = sqlite3_column_int(pSquery, 1);
    shell = sqlite3_column_text(pSquery, 2);
    homedir = sqlite3_column_text(pSquery, 3);

    fill_passwd(pwbuf, buf, buflen, name, "x", uid, gid, "", shell, homedir, errnop);
   
    free(query);
    sqlite3_finalize(pSquery);
    sqlite3_close(pDb);

    return NSS_STATUS_SUCCESS;
}

