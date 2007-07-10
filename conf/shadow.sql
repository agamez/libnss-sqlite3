CREATE TABLE shadow (username TEXT, passwd TEXT);

CREATE INDEX idx_shadow_username ON shadow(username);
