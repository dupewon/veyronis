pub mod block;
pub mod error;
pub mod header;
pub mod manifest;
pub mod reader;
pub mod trailer;
pub mod writer;

pub use block::{
    BlockEntry, BLOCK_TYPE_EVENTS, BLOCK_TYPE_GRAPH, BLOCK_TYPE_MANIFEST, BLOCK_TYPE_RAW_EVIDENCE,
};
pub use error::FormatError;
pub use header::{
    VyrHeader, CURRENT_MAJOR_VERSION, CURRENT_MINOR_VERSION, FLAG_COMPRESSED, FLAG_ENCRYPTED,
    FLAG_SIGNED, MAGIC_BYTES,
};
pub use manifest::ArtifactManifest;
pub use reader::{DecryptedArtifact, VyrReader};
pub use trailer::VyrTrailer;
pub use writer::VyrWriter;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use veyronis_crypto::{RecipientKeypair, RecipientPublicKey, SigningKeypair};
    use veyronis_graph::BehaviorGraph;
    use veyronis_ir::categories::{EventData, ProcessStartData};
    use veyronis_ir::event::{EventType, Platform, VirEvent};
    use veyronis_ir::identity::ProcessIdentity;

    fn create_sample_event() -> VirEvent {
        let proc = ProcessIdentity::new(1001, None, 12345, "/usr/bin/curl", 1);
        VirEvent::new(
            proc,
            EventType::ProcessStart,
            EventData::ProcessStart(ProcessStartData {
                executable_path: "/usr/bin/curl".into(),
                command_line: vec!["curl".into(), "https://example.com".into()],
                working_directory: None,
                parent_pid: None,
                environment_keys: vec![],
            }),
            "test-collector",
        )
    }

    #[test]
    fn test_vyr_format_write_read_roundtrip() {
        let signing_key = SigningKeypair::generate();
        let recipient_key = RecipientKeypair::generate();
        let recipient_pub = RecipientPublicKey::from_x25519(recipient_key.public_key(), "test-key");

        let event = create_sample_event();
        let events = vec![event.clone()];
        let graph = BehaviorGraph::from_events(events.clone());

        let manifest = ArtifactManifest::new(
            vec!["curl".into(), "https://example.com".into()],
            1001,
            Platform::Linux,
            chrono::Utc::now(),
            chrono::Utc::now(),
        );

        let mut writer = VyrWriter::new(signing_key);
        writer.add_recipient_public_key(&recipient_pub).unwrap();
        writer.write_manifest(&manifest).unwrap();
        writer.write_events(&events).unwrap();
        writer.write_graph(&graph).unwrap();

        let mut buffer = Vec::new();
        writer.write_to(&mut buffer).expect("write artifact");

        // Verify container structure without decrypting
        let mut cursor = Cursor::new(buffer.clone());
        let reader = VyrReader::read_from(&mut cursor).expect("read container");
        assert!(reader.verify_integrity_and_signature().is_ok());

        // Decrypt with recipient private key
        let decrypted = reader
            .decrypt_with_key(&recipient_key)
            .expect("decryption succeeds");
        assert_eq!(decrypted.events.len(), 1);
        assert_eq!(decrypted.events[0].event_id, event.event_id);
        assert!(decrypted.manifest.is_some());
        assert!(decrypted.graph.is_some());
    }

    #[test]
    fn test_vyr_format_tamper_detection() {
        let signing_key = SigningKeypair::generate();
        let recipient_key = RecipientKeypair::generate();
        let recipient_pub = RecipientPublicKey::from_x25519(recipient_key.public_key(), "test-key");

        let events = vec![create_sample_event()];
        let mut writer = VyrWriter::new(signing_key);
        writer.add_recipient_public_key(&recipient_pub).unwrap();
        writer.write_events(&events).unwrap();

        let mut buffer = Vec::new();
        writer.write_to(&mut buffer).unwrap();

        // Corrupt a byte in the ciphertext body
        let corrupt_idx = buffer.len() - 100;
        buffer[corrupt_idx] ^= 0xAA;

        let mut cursor = Cursor::new(buffer);
        let reader_res = VyrReader::read_from(&mut cursor);
        if let Ok(reader) = reader_res {
            let verify_res = reader.verify_integrity_and_signature();
            assert!(verify_res.is_err());
        }
    }

    #[test]
    fn test_vyr_wrong_passphrase_rejection() {
        let signing_key = SigningKeypair::generate();
        let mut writer = VyrWriter::new(signing_key);
        writer
            .add_passphrase_recipient(b"SecretPassphrase123")
            .unwrap();
        writer.write_events(&[create_sample_event()]).unwrap();

        let mut buffer = Vec::new();
        writer.write_to(&mut buffer).unwrap();

        let mut cursor = Cursor::new(buffer);
        let reader = VyrReader::read_from(&mut cursor).unwrap();

        assert!(reader.decrypt_with_passphrase(b"WrongPassphrase").is_err());
        assert!(reader
            .decrypt_with_passphrase(b"SecretPassphrase123")
            .is_ok());
    }
}
