use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unsupported link scheme: {0}")]
    UnsupportedScheme(String),

    #[error("malformed link: {0}")]
    MalformedLink(String),

    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    #[error("invalid value for `{field}`: {value}")]
    InvalidValue { field: String, value: String },

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("failed to decode base64: {0}")]
    Base64(String),

    #[error("failed to decode json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("failed to decode yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("invalid url: {0}")]
    Url(#[from] url::ParseError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("format detection failed: content looks like neither links, xray json, sing-box json nor mihomo yaml")]
    Detection,

    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("geoip error: {0}")]
    GeoIp(String),

    #[error("geo api error: {0}")]
    GeoApi(String),

    #[error("probe error: {0}")]
    Probe(String),

    #[error("subscription fetch error: {0}")]
    Fetch(String),

    #[error("balancer error: {0}")]
    Balancer(String),

    #[error("{0}")]
    Unrepresentable(String),
}

pub type ResultExt<T> = std::result::Result<T, Error>;

pub(crate) fn field_err<F: Into<String>, V: std::fmt::Display>(field: F, value: V) -> Error {
    Error::InvalidValue {
        field: field.into(),
        value: value.to_string(),
    }
}
