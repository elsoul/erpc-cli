// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Talking to an RPC endpoint rather than running a node: one JSON-RPC
//! request, the webhook subscriptions defined on this machine, and their
//! delivery.

pub(crate) mod call;
pub(crate) mod webhook;
pub(crate) mod webhook_delivery;
