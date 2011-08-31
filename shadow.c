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
 * shadow.c : Functions handling shadow entries retrieval.
 */

#include "nss-sqlite.h"
#include "utils.h"

#include <errno.h>
#include <grp.h>
#include <malloc.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

/*
 * struct used to store data used by getspent.
 */
static struct {
    sqlite3* pDb;
    sqlite3_stmt* pSt;
    int try_again;      /* flag to know if NSS_TRYAGAIN
                            was returned by previous call
                            to getspent_r */
    /* user information cache used if NSS_TRYAGAIN was returned */
    struct spwd entry;
} spent_data = { NULL, NULL, 0, NULL};

/* mutex used to serialize xxspent operation */
pthread_mutex_t spent_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;


/**
 * Setup everything needed to retrieve shadow entries.
 */
enum nss_status _nss_sqlite_setspent(void) {
    char* sql;
    pthread_mutex_lock(&spent_mutex);
    if(spent_data.pDb == NULL) {
        NSS_DEBUG("setspent: opening DB connection\n");
        if(sqlite3_open(NSS_SQLITE_SHADOW_DB, &spent_data.pDb) != SQLITE_OK) {
            NSS_ERROR(sqlite3_errmsg(spent_data.pDb));
            return NSS_STATUS_UNAVAIL;
        }
        if(!(sql = get_query(spent_data.pDb, "setspent")) ) {
            NSS_ERROR(sqlite3_errmsg(spent_data.pDb));
            sqlite3_close(spent_data.pDb);
            return NSS_STATUS_UNAVAIL;
        }
        if(sqlite3_prepare(spent_data.pDb, sql, -1, &spent_data.pSt, NULL) != SQLITE_OK) {
            NSS_ERROR(sqlite3_errmsg(spent_data.pDb));
            sqlite3_finalize(spent_data.pSt);
            sqlite3_close(spent_data.pDb);
            free(sql);
            return NSS_STATUS_UNAVAIL;
        }
    }
    free(sql);
    pthread_mutex_unlock(&spent_mutex);
    return NSS_STATUS_SUCCESS;
}

/*
 * Free getspent resources.
 */
enum nss_status _nss_sqlite_endspent(void) {
    NSS_DEBUG("endspent: finalizing shadow serial access facilities\n");
    pthread_mutex_lock(&spent_mutex);
    if(spent_data.pDb != NULL) {
        sqlite3_finalize(spent_data.pSt);
        sqlite3_close(spent_data.pDb);
        spent_data.pDb = NULL;
    }
    pthread_mutex_unlock(&spent_mutex);
    return NSS_STATUS_SUCCESS;
}

/*
 * Return next shadow entry. see man getspent_r
 * @param pwbuf Buffer to store shadow data.
 * @param buf Buffer which will contain all string pointed
 * to by pwbuf entries.
 * @param buflen buf length.
 * @param errnop Pointer to errno, will be filled if
 * an error occurs.
 */

enum nss_status
_nss_sqlite_getspent_r(struct spwd *spbuf, char *buf,
                      size_t buflen, int *errnop) {
    int res;
    NSS_DEBUG("getspent_r\n");
    pthread_mutex_lock(&spent_mutex);

    if(spent_data.pDb == NULL) {
        _nss_sqlite_setspent();
    }

    if(spent_data.try_again) {
        res = fill_shadow(spbuf, buf, buflen, spent_data.entry, errnop);
        /* buffer was long enough this time */
        if(res != NSS_STATUS_TRYAGAIN || (*errnop) != ERANGE) {
            spent_data.try_again = 0;
            pthread_mutex_unlock(&spent_mutex);
            return res;
        }
    }

    res = res2nss_status(sqlite3_step(spent_data.pSt), spent_data.pDb, spent_data.pSt);
    if(res != NSS_STATUS_SUCCESS) {
        spent_data.pDb = NULL;
        pthread_mutex_unlock(&spent_mutex);
        return res;
    }

    fill_shadow_sql(&spent_data.entry, spent_data.pSt);
    res = fill_shadow(spbuf, buf, buflen, spent_data.entry, errnop);

    NSS_DEBUG("getspent_r: fetched user %s\n", spent_data.entry.sp_namp);

    if(res == NSS_STATUS_TRYAGAIN && (*errnop) == ERANGE) {
        /* cache result for next try */
        spent_data.try_again = 1;

        pthread_mutex_unlock(&spent_mutex);
        return NSS_STATUS_TRYAGAIN;
    }
    pthread_mutex_unlock(&spent_mutex);
    return NSS_STATUS_SUCCESS;
}




/*
 * Get shadow information using username.
 */

enum nss_status _nss_sqlite_getspnam_r(const char* name, struct spwd *spbuf,
               char *buf, size_t buflen, int *errnop) {
    sqlite3 *pDb;
    struct sqlite3_stmt* pSquery;
    int res;
    struct spwd entry;
    char* query;

    NSS_DEBUG("getspnam_r: looking for user %s (shadow)\n", name);

    if(sqlite3_open(NSS_SQLITE_SHADOW_DB, &pDb) != SQLITE_OK) {
        NSS_ERROR(sqlite3_errmsg(pDb));
        sqlite3_close(pDb);
        return NSS_STATUS_UNAVAIL;
    }

    if(!(query = get_query(pDb, "getspnam_r")) ) {
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

    fill_shadow_sql(&entry, pSquery);
    res = fill_shadow(spbuf, buf, buflen, entry, errnop);

    free(query);
    sqlite3_finalize(pSquery);
    sqlite3_close(pDb);

    return res;
}
