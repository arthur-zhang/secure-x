#[derive(Debug)]
pub enum ApiError {
    RuleExists,
    InvalidRequest,
    RuleNotFound,
    FileError,
}