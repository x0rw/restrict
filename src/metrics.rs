/// restrict metrics wrapper
#[cfg(feature = "metrics")]
#[macro_export]
macro_rules! restrict_counter {
    ($name:expr, $value:expr $(, $label:expr => $value_expr:expr)*) => {
        ::metrics::counter!(
            $name,
            $value,
            $($label => $value_expr,)*
        )
    };
}

/// restrict metrics wrapper
#[cfg(not(feature = "metrics"))]
#[macro_export]
macro_rules! restrict_counter {
    ($name:expr, $value:expr $(, $label:expr => $value_expr:expr)*) => {
        if false {
            let _ = ($name, $value $(, $label, $value_expr)*);
        }
    };
}
