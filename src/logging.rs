/// tracing wrapper
#[cfg(feature = "logging")]
#[macro_export]
macro_rules! restrict_error {
    ($($arg:tt)+) => {
        tracing::error!($($arg)+)
    };
}

/// tracing wrapper
#[cfg(not(feature = "logging"))]
#[macro_export]
macro_rules! restrict_error {
    ($($arg:tt)+) => {{}}; // Complete no-op
}
/// tracing wrapper
#[cfg(feature = "logging")]
#[macro_export]
macro_rules! restrict_info {
    ($msg:expr) => {
        tracing::info!("{}", $msg)
    };

    ($msg:literal, $($key:ident = $value:expr),+ $(,)?) => {
        tracing::info!(
            $msg,
            $($key = $value,)+
        )
    };

    ($($key:ident => $value:expr),+ $(,)?) => {
        tracing::info!(
            $($key = $value,)+
        )
    };
}

/// tracing wrapper
#[cfg(not(feature = "logging"))]
#[macro_export]
macro_rules! restrict_info {
    ( $($arg:expr),+ $(,)? ) => {{
        $(
            let _ = &$arg;
        )+
    }};
}

/// tracing wrapper
#[cfg(feature = "logging")]
#[macro_export]
macro_rules! restrict_warn {
    ($($arg:tt)+) => {
        tracing::warn!($($arg)+)
    };
}

/// tracing wrapper
#[cfg(not(feature = "logging"))]
#[macro_export]
macro_rules! restrict_warn {
    ($($arg:tt)+) => {{}};
}
