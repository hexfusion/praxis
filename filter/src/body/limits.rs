// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Shared body-size defaults for built-in filters.

// -----------------------------------------------------------------------------
// Body Size Constants
// -----------------------------------------------------------------------------

/// Default maximum body size for generic JSON request-body inspection (10 MiB).
pub(crate) const DEFAULT_JSON_BODY_MAX_BYTES: usize = 10_485_760; // 10 MiB
