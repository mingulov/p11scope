//! SPDX-License-Identifier: GPL-3.0-or-later
//! Shared ordinary-entry decision seam and its map/helper boundary.

use super::{
    CallerEvidence, CallerObjectKey, CallerObjectUse, EndpointObject, CALLER_USE_POSITIVE,
};
use crate::ImageIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairInsertError {
    Exists,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallerEntryFailure {
    GlobalStateInvalid,
    Caller(CallerEvidence),
}

/// The BPF adapter supplies these operations after scope, ABI, config and
/// attach-cookie authorization. Test adapters use bounded storage and the same
/// decision function, without providing a second caller-recording algorithm.
pub trait CallerEntryIo {
    fn endpoint_object(&mut self, endpoint: u32) -> Option<EndpointObject>;
    fn mark_usage(&mut self, endpoint: u32) -> bool;
    fn current_identity(&mut self) -> Option<ImageIdentity>;
    fn lookup(&mut self, key: &CallerObjectKey) -> Option<CallerObjectUse>;
    fn insert_noexist(
        &mut self,
        key: &CallerObjectKey,
        value: &CallerObjectUse,
    ) -> Result<(), PairInsertError>;
    fn now_ns(&mut self) -> u64;
}

/// Preserve one positive witness for each exact image/physical-object pair.
/// An already-positive global bit never skips the current caller lookup.
#[inline(always)]
pub fn record_caller_use_with<I: CallerEntryIo>(
    io: &mut I,
    endpoint: u32,
    endpoint_capacity: u32,
    host_tgid: u32,
) -> Result<(), CallerEntryFailure> {
    use CallerEntryFailure::Caller;
    if endpoint >= endpoint_capacity {
        return Err(Caller(CallerEvidence::InvalidEndpointObject));
    }
    let object_id = io
        .endpoint_object(endpoint)
        .and_then(EndpointObject::committed_object_id)
        .ok_or(Caller(CallerEvidence::InvalidEndpointObject))?;
    if !io.mark_usage(endpoint) {
        return Err(CallerEntryFailure::GlobalStateInvalid);
    }
    let image = io
        .current_identity()
        .filter(|image| image.task_cookie != 0)
        .ok_or(Caller(CallerEvidence::IdentityUnavailable))?;
    let key = CallerObjectKey {
        image,
        object_id,
        reserved: 0,
    };
    if let Some(value) = io.lookup(&key) {
        return validate_pair_with(io, &key, value, endpoint_capacity, host_tgid);
    }
    let mut value = CallerObjectUse {
        recorded_at_ns: 0,
        recent_bucket: 0,
        host_tgid,
        witness_endpoint: endpoint,
        flags: CALLER_USE_POSITIVE,
        reserved: 0,
    };
    if !value.is_valid(endpoint_capacity) {
        return Err(Caller(CallerEvidence::PairIntegrityFailure));
    }
    value.recorded_at_ns = io.now_ns();
    match io.insert_noexist(&key, &value) {
        Ok(()) => Ok(()),
        Err(PairInsertError::Failed) => Err(Caller(CallerEvidence::PairInsertFailure)),
        Err(PairInsertError::Exists) => {
            let winner = io
                .lookup(&key)
                .ok_or(Caller(CallerEvidence::PairIntegrityFailure))?;
            validate_pair_with(io, &key, winner, endpoint_capacity, host_tgid)
        }
    }
}

#[inline(always)]
fn validate_pair_with<I: CallerEntryIo>(
    io: &mut I,
    key: &CallerObjectKey,
    value: CallerObjectUse,
    endpoint_capacity: u32,
    host_tgid: u32,
) -> Result<(), CallerEntryFailure> {
    if value.is_valid(endpoint_capacity)
        && value.host_tgid == host_tgid
        && io
            .endpoint_object(value.witness_endpoint)
            .and_then(EndpointObject::committed_object_id)
            == Some(key.object_id)
    {
        Ok(())
    } else {
        Err(CallerEntryFailure::Caller(
            CallerEvidence::PairIntegrityFailure,
        ))
    }
}

#[cfg(test)]
mod tests;
