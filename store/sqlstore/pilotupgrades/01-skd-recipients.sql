-- v0 -> v1: PILOT-STATUS FORK (group SKD tracking): devices known to hold our group sender key
CREATE TABLE whatsmeow_pilot_skd_recipients (
	our_jid    TEXT,
	chat_id    TEXT,
	device_jid TEXT,
	their_id   TEXT   NOT NULL,
	key_id     BIGINT NOT NULL,
	iteration  BIGINT NOT NULL,
	sent_at    BIGINT NOT NULL,

	PRIMARY KEY (our_jid, chat_id, device_jid),
	FOREIGN KEY (our_jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX whatsmeow_pilot_skd_recipients_their_id_idx ON whatsmeow_pilot_skd_recipients (our_jid, their_id);
