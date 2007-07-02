CREATE TABLE shadow(uid INTEGER PRIMARY KEY, gid INTEGER, username TEXT NOT NULL, passwd TEXT NOT NULL, gecos TEXT NOT NULL default '', shell TEXT NOT NULL,  homedir TEXT NOT NULL);
CREATE INDEX idx_username ON shadow(username);
CREATE TABLE user_group(uid INTEGER, gid INTEGER, CONSTRAINT pk_user_groups PRIMARY KEY(uid, gid));
CREATE TABLE groups(gid INTEGER PRIMARY KEY, groupname TEXT NOT NULL, passwd TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_groupname ON groups(groupname);

