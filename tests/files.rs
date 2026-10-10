use codepass::source_hash;
use std::fs;

#[test]
fn files_are_read_only_and_bounded() {
    let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("source.bin");
    let source = b"\xff\0print('hello')\r\n";
    fs::write(&path, source).unwrap(); let a = source_hash(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), source);
    fs::write(&path, b"\xff\0print('hello')\n").unwrap();
    assert_ne!(a, source_hash(&path).unwrap());
    fs::write(&path, vec![0; 1024 * 1024]).unwrap(); assert!(source_hash(&path).is_ok());
    fs::write(&path, vec![0; 1024 * 1024 + 1]).unwrap(); assert!(source_hash(&path).is_err());
    assert!(source_hash(dir.path()).is_err());
    assert!(source_hash(&dir.path().join("missing")).is_err());
}
