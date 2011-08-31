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
#include <pthread.h>

/*
 * struct used to store data used by getpwent.
 */
static struct {
    sqlite3* pDb;
    sqlite3_stmt* pSt;
    int try_again;      /* flag to know if NSS_TRYAGAIN
                            was returned by previous call
                            to getpwent_r */
    /* user information cache used if NSS_TRYAGAIN was returned */
    const unsigned char* name;
    uid_t uid;
    gid_t gid;
    const unsigned char* shell;
    const unsigned char* homedir;
} pwent_data = { NULL, NULL, 0, NULL, 0, 0, NULL, NULL };

/* mutex used to serialize xxpwent operation */
pthread_mutex_t pwent_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;


/**
 * Setup everything needed to retrieve passwd entries.
 */
enum nss_status _nss_sqlite_setpwent(void) {
    char* sql;
    pthread_mutex_lock(&pwent_mutex);
    if(pwent_data.pDb == NULL) {
        NSS_DEBUG("setpwent: opening DB connection\n");
        if(sqlite3_open(NSS_SQLITE_PASSWD_DB, &pwent_data.pDb) != SQLITE_OK) {
            NSS_ERROR(sqlite3_errmsg(pwent_data.pDb));
            return NSS_STATUS_UNAVAIL;
        }
        if(!(sql = get_query(pwent_data.pDb, "setpwent")) ) {
            NSS_ERROR(sqlite3_errmsg(pwent_data.pDb));
            sqlite3_close(pwent_data.pDb);
            return NSS_STATUS_UNAVAIL;
        }
        if(sqlite3_prepare(pwent_data.pDb, sql, -1, &pwent_data.pSt, NULL) != SQLITE_OK) {
            NSS_ERROR(sqlite3_errmsg(pwent_data.pDb));
            sqlite3_finalize(pwent_data.pSt);
            sqlite3_close(pwent_data.pDb);
            free(sql);
            return NSS_STATUS_UNAVAIL;
        }
    }
    free(sql);
    pthread_mutex_unlock(&pwent_mutex);
    return NSS_STATUS_SUCCESS;
}

/*
 * Free getpwent resources.
 */
enum nss_status _nss_sqlite_endpwent(void) {
    NSS_DEBUG("endpwent: finalizing passwd serial access facilities\n");
    pthread_mutex_lock(&pwent_mutex);
    if(pwent_data.pDb != NULL) {
        sqlite3_finalize(pwent_data.pSt);
        sqlite3_close(pwent_data.pDb);
        pwent_data.pDb = NULL;
    }
    pthread_mutex_unlock(&pwent_mutex);
    return NSS_STATUS_SUCCESS;
}

/*
 * Return next passwd entry. see man getpwent_r
 * @param pwbuf Buffer to store passwd data.
 * @param buf Buffer which will contain all string pointed
 * to by pwbuf entries.
 * @param buflen buf length.
 * @param errnop Pointer to errno, will be filled if
 * an error occurs.
 */

enum nss_status
_nss_sqlite_getpwent_r(struct passwd *pwbuf, char *buf,
                      size_t buflen, int *errnop) {
    int res;
    const unsigned char* name;
    uid_t uid;
    gid_t gid;
    const unsigned char* shell;
    const unsigned char* homedir;
    NSS_DEBUG("getpwent_r\n");
    pthread_mutex_lock(&pwent_mutex);

    if(pwent_data.pDb == NULL) {
        _nss_sqlite_setpwent();
    }

    if(pwent_data.try_again) {
        res = fill_passwd(pwbuf, buf, buflen, name, "x", uid, gid, "", shell, homedir, errnop);
        /* buffer was long enough this time */
        if(res != NSS_STATUS_TRYAGAIN || (*errnop) != ERANGE) {
            pwent_data.try_again = 0;
            pthread_mutex_unlock(&pwent_mutex);
            return res;
        }
    }

    res = res2nss_status(sqlite3_step(pwent_data.pSt), pwent_data.pDb, pwent_data.pSt);
    if(res != NSS_STATUS_SUCCESS) {
        pwent_data.pDb = NULL;
        pthread_mutex_unlock(&pwent_mutex);
        return res;
    }
    uid = sqlite3_column_int(pwent_data.pSt, 0);
    gid = sqlite3_column_int(pwent_data.pSt, 1);
    name = sqlite3_column_text(pwent_data.pSt, 2);
    shell = sqlite3_column_text(pwent_data.pSt, 3);
    homedir = sqlite3_column_text(pwent_data.pSt, 4);

    NSS_DEBUG("getpwent_r: fetched user #%d: %s\n", uid, name);

    res = fill_passwd(pwbuf, buf, buflen, name, "x", uid, gid, "", shell, homedir, errnop);
    if(res == NSS_STATUS_TRYAGAIN && (*errnop) == ERANGE) {
        /* cache result for next try */
        pwent_data.uid = uid;
        pwent_data.gid = gid;
        pwent_data.name = name;
        pwent_data.shell = shell;
        pwent_data.homedir = homedir;
        pwent_data.try_again = 1;

        pthread_mutex_unlock(&pwent_mutex);
        return NSS_STATUS_TRYAGAIN;
    }
    pthread_mutex_unlock(&pwent_mutex);
    return NSS_STATUS_SUCCESS;
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

