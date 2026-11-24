pub(crate) const WINDOWS: bool = cfg!(target_os = "windows");

/// Disable QUIC UDP segmentation offload on Windows, where some drivers stall coalesced sends.
pub(crate) const fn segmentation_offload(windows: bool) -> bool {
    !windows
}

#[cfg(test)]
mod tests {
    use super::segmentation_offload;

    #[test]
    fn segmentation_offload_is_disabled_only_on_windows() {
        assert!(!segmentation_offload(true));
        assert!(segmentation_offload(false));
    }
}
