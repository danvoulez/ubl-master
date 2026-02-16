use lazy_static::lazy_static;
lazy_static! {
    pub static ref BASE_URL: String =
        std::env::var("REGISTRY_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".into());
}
