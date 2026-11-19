// Rebuild when a migration is added; sqlx::migrate! does not track new files on its own.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
