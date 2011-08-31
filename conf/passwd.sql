CREATE TABLE passwd(uid INTEGER PRIMARY KEY, username TEXT NOT NULL, gid INTEGER, gecos TEXT NOT NULL default ',,,', homedir TEXT NOT NULL, shell TEXT NOT NULL);
CREATE INDEX idx_passwd_username ON passwd(username);

CREATE TABLE user_group(uid INTEGER, gid INTEGER, CONSTRAINT pk_user_groups PRIMARY KEY(uid, gid));
CREATE INDEX idx_ug_uid ON user_group(uid);
CREATE INDEX idx_ug_gid ON user_group(gid);

CREATE TABLE groups(gid INTEGER PRIMARY KEY, groupname TEXT NOT NULL, passwd TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_groupname ON groups(groupname);

CREATE TABLE nss_queries(name TEXT PRIMARY KEY, query TEXT NOT NULL);
INSERT INTO nss_queries VALUES("setpwent", "SELECT uid, username, gid, gecos, homedir, shell FROM passwd;");
INSERT INTO nss_queries VALUES("getpwnam_r","SELECT uid, gid, shell, homedir FROM passwd WHERE username = ?");
INSERT INTO nss_queries VALUES("getpwuid_r","SELECT username, gid, shell, homedir FROM passwd WHERE uid = ?");


INSERT INTO nss_queries VALUES("setgrent", "SELECT gid, groupname, passwd FROM groups");
INSERT INTO nss_queries VALUES("getgrnam_r", "SELECT gid, passwd FROM groups WHERE groupname = ?");
INSERT INTO nss_queries VALUES("getgrgid_r", "SELECT groupname, passwd FROM groups WHERE gid = ?");

INSERT INTO nss_queries VALUES("initgroups_dyn", "SELECT ug.gid FROM user_group ug INNER JOIN passwd p ON p.uid = ug.uid WHERE p.username = ? AND ug.gid != ?");
INSERT INTO nss_queries VALUES("get_users", "SELECT username FROM passwd u INNER JOIN user_group ug ON ug.uid = u.uid WHERE ug.gid = ?");
