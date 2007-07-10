CREATE TABLE passwd(uid INTEGER PRIMARY KEY, gid INTEGER, username TEXT NOT NULL, gecos TEXT NOT NULL default '', shell TEXT NOT NULL,  homedir TEXT NOT NULL);
CREATE INDEX idx_passwd_username ON passwd(username);

CREATE TABLE user_group(uid INTEGER, gid INTEGER, CONSTRAINT pk_user_groups PRIMARY KEY(uid, gid));
CREATE INDEX idx_ug_uid ON user_group(uid);
CREATE INDEX idx_ug_gid ON user_group(gid);

CREATE TABLE groups(gid INTEGER PRIMARY KEY, groupname TEXT NOT NULL, passwd TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_groupname ON groups(groupname);

