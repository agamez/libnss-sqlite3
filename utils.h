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

#ifndef NSS_SQLITE_UTILS_H
#define NSS_SQLITE_UTILS_H

#include <sqlite3.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>

char *get_query(struct sqlite3*, char*);
enum nss_status fill_passwd_buf(struct passwd, char*, size_t, int*) ;
enum nss_status fill_shadow(struct spwd*, char*, size_t, const char*,
    const char*, long, long, long, long, long, long, int*);
enum nss_status fill_group(struct sqlite3*, struct group*, char*, size_t,
    const unsigned char*, const unsigned char*, gid_t, int*);

#endif
