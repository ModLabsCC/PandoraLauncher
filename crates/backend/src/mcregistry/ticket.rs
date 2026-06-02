use std::{fs::File, path::Path};

use rc_zip_sync::rc_zip::EntryKind;
use schema::mcregistry::{McRegistryTicket, MCREGISTRY_TICKET_ZIP_PATH};
use sha1::{Digest, Sha1};

use super::McRegistryError;

pub struct TicketFromJar {
    pub file_sha1: [u8; 20],
    pub ticket: McRegistryTicket,
}

pub fn read_ticket_with_hash_from_path(path: &Path) -> Result<Option<TicketFromJar>, McRegistryError> {
    let file_sha1 = sha1_of_path(path)?;
    let file = File::open(path)?;
    parse_ticket_from_reader(file).map(|ticket| {
        ticket.map(|ticket| TicketFromJar { file_sha1, ticket })
    })
}

pub fn read_ticket_with_hash_from_bytes(bytes: &[u8]) -> Result<Option<TicketFromJar>, McRegistryError> {
    let file_sha1 = sha1_of_bytes(bytes);
    parse_ticket_from_reader(bytes).map(|ticket| {
        ticket.map(|ticket| TicketFromJar { file_sha1, ticket })
    })
}

pub fn sha1_of_path(path: &Path) -> Result<[u8; 20], McRegistryError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha1::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hasher.finalize().into())
}

pub fn sha1_of_bytes(bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn parse_ticket_from_reader(reader: impl rc_zip_sync::ReadZip) -> Result<Option<McRegistryTicket>, McRegistryError> {
    let Ok(archive) = reader.read_zip() else {
        return Err(McRegistryError::InvalidArchive);
    };

    for entry in archive.entries() {
        if entry.kind() != EntryKind::File {
            continue;
        }

        if entry.name != MCREGISTRY_TICKET_ZIP_PATH {
            continue;
        }

        let bytes = entry.bytes().map_err(|_| McRegistryError::InvalidArchive)?;
        let mut ticket: McRegistryTicket = serde_json::from_slice(&bytes)?;
        normalize_ticket(&mut ticket);
        return Ok(Some(ticket));
    }

    Ok(None)
}

fn normalize_ticket(ticket: &mut McRegistryTicket) {
    let artifact_sha256 = ticket.artifact_sha256.to_ascii_lowercase();
    if artifact_sha256 != ticket.artifact_sha256.as_ref() {
        ticket.artifact_sha256 = artifact_sha256.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ticket_from_zip_bytes() {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;

        let ticket_json = br#"{"version":1,"ticket_id":"550e8400-e29b-41d4-a716-446655440000","artifact_sha256":"a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456","developer_sub":"authentik|abc123","entitlements":{},"issued_at":"2026-06-02T16:33:21Z","notary_issuer":"mcregistry"}"#;

        let mut buffer = Vec::new();
        {
            let mut zip = ZipWriter::new(std::io::Cursor::new(&mut buffer));
            zip.start_file(
                MCREGISTRY_TICKET_ZIP_PATH,
                SimpleFileOptions::default(),
            )
            .unwrap();
            zip.write_all(ticket_json).unwrap();
            zip.finish().unwrap();
        }

        let parsed = read_ticket_with_hash_from_bytes(&buffer).unwrap().unwrap();
        assert_eq!(parsed.ticket.version, 1);
        assert_eq!(parsed.ticket.notary_issuer.as_ref(), "mcregistry");
        assert_eq!(
            parsed.ticket.artifact_sha256.as_ref(),
            "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
        );
        assert_eq!(parsed.file_sha1, sha1_of_bytes(&buffer));
    }
}
