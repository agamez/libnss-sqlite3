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
#include <shadow.h>
#include <sqlite3.h>
#include <string.h>


/* Query the DB itself for the SQL query that is needed to resolve the call to getent function
 * @param pDb Database handle, will be closed if something fails.
 * @param getent_function The name of the getent function for which SQL statement is going to be retrieved.
 */
char *get_query(struct sqlite3* pDb, char *getent_function) {
    struct sqlite3_stmt* pSsql;
    const char* sql = "SELECT query FROM nss_queries WHERE name = ?";
    char *query;
    int res;

    if(sqlite3_prepare(pDb, sql, -1, &pSsql, NULL) != SQLITE_OK) {
        NSS_ERROR(sqlite3_errmsg(pDb));
        sqlite3_finalize(pSsql);
        sqlite3_close(pDb);
        return NULL;
    }

    if(sqlite3_bind_text(pSsql, 1, getent_function, -1, SQLITE_STATIC) != SQLITE_OK) {
        NSS_DEBUG(sqlite3_errmsg(pDb));
        sqlite3_finalize(pSsql);
        sqlite3_close(pDb);
        return NULL;
    }

    res = res2nss_status(sqlite3_step(pSsql), pDb, pSsql);
    if(res != NSS_STATUS_SUCCESS) {
        sqlite3_finalize(pSsql);
        sqlite3_close(pDb);
        return NULL;
    }

    query = strdup(sqlite3_column_text(pSsql, 0));
    sqlite3_finalize(pSsql);
    return query;
}

/*
 * Translate sqlite return code into a directly usable nss_status code.
 * @param pDb Database handle, will be closed if something fails.
 * @param pSt Statement to fetch from, will be finalized if something
 *      goes wrong.
 */

enum nss_status res2nss_status(int res, struct sqlite3* pDb, struct sqlite3_stmt* pSt) {
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
    int res;

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
    res = get_users(pDb, gbuf->gr_gid, buf, buflen - total_length, errnop);
    if(res == NSS_STATUS_SUCCESS) {
        gbuf->gr_mem = (char**)buf;
    }

    return res;
}


/*
 * Fill a passwd struct using given information.
 * @param pwbuf Struct which will be filled with various info.
 * @param buf Buffer which will contain all strings pointed to by
 *      pwbuf.
 * @param buflen Buffer length.
 * @param entry Passwd entry with needed data.
 * @param errnop Pointer to errno, will be filled if something goes wrong.
 */

enum nss_status fill_passwd(struct passwd* pwbuf, char* buf, size_t buflen, struct passwd entry, int* errnop) {
    int name_length = strlen(entry.pw_name) + 1;
    int pw_length = strlen(entry.pw_passwd) + 1;
    int gecos_length = strlen(entry.pw_gecos) + 1;
    int homedir_length = strlen(entry.pw_dir) + 1;
    int shell_length = strlen(entry.pw_shell) + 1;

    int total_length = name_length + pw_length + gecos_length + shell_length + homedir_length;

    if(buflen < total_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    pwbuf->pw_uid = entry.pw_uid;
    pwbuf->pw_gid = entry.pw_gid;

    strcpy(buf, entry.pw_name);
    pwbuf->pw_name = buf;
    buf += name_length;

    strcpy(buf, entry.pw_passwd);
    pwbuf->pw_passwd = buf;
    buf += pw_length;

    strcpy(buf, entry.pw_gecos);
    pwbuf->pw_gecos = buf;
    buf += gecos_length;

    strcpy(buf, entry.pw_dir);
    pwbuf->pw_dir = buf;
    buf += homedir_length;

    strcpy(buf, entry.pw_shell);
    pwbuf->pw_shell = buf;


    return NSS_STATUS_SUCCESS;
}

inline void fill_passwd_sql(struct passwd* entry, struct sqlite3_stmt* pSquery) {
    entry->pw_name = sqlite3_column_text(pSquery, 0);
    entry->pw_passwd = sqlite3_column_text(pSquery, 1);
    entry->pw_uid = sqlite3_column_int(pSquery, 2);
    entry->pw_gid =sqlite3_column_int(pSquery, 3);
    entry->pw_gecos = sqlite3_column_text(pSquery, 4);
    entry->pw_dir = sqlite3_column_text(pSquery, 5);
    entry->pw_shell = sqlite3_column_text(pSquery, 6);

    return;
}


/*
 * Fill an shadow password struct using given information.
 * @param spbuf Struct which will be filled with various info.
 * @param buf Buffer which will contain all strings pointed to by
 *      pwbuf.
 * @param buflen Buffer length.
 * @param name Username.
 * @param pw Encrypted password.
 * @param lstchg Date of last change (measured in days since 1970-01-01 00:00:00 +0000 (UTC))
 * @param min Min # of days between changes
 * @param max Max # of days between changes
 * @param warn # of days before password expires to warn user to change it
 * @param inact # of days after password expires until account is disabled
 * @param expire Date when account expires (measured in days since 1970-01-01 00:00:00 +0000 (UTC))
 * @param errnop Pointer to errno, will be filled if something goes wrong.
 */

enum nss_status fill_shadow(struct spwd *spbuf, char* buf, size_t buflen,
    const char* name, const char* pw, long lstchg, long min, long max, long warn,
    long inact, long expire, int* errnop) {

    int name_length = strlen(name) + 1;
    int pw_length = strlen(pw) + 1;
    if(buflen < name_length + pw_length) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    strcpy(buf, name);
    spbuf->sp_namp = buf;
    buf += name_length;
    strcpy(buf, pw);
    spbuf->sp_pwdp = buf;
    spbuf->sp_lstchg = -1;
    spbuf->sp_min = -1;
    spbuf->sp_max = -1;
    spbuf->sp_warn = -1;
    spbuf->sp_inact = -1;
    spbuf->sp_expire = -1;

    return NSS_STATUS_SUCCESS;
}
