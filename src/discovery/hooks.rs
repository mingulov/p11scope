//! Which exported symbols hand out a PKCS#11 function table, and with what ABI.
//! Built-ins cover the standard three plus NSS's `NSC_`/`FC_` pair; `--hook-symbol`
//! adds vendor names (spec §2, §4.3).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAbi {
    /// `CK_RV f(CK_FUNCTION_LIST_PTR_PTR)` — the table is written to `*arg0`.
    FunctionList,
    /// `CK_RV f(CK_INTERFACE_PTR, CK_ULONG_PTR)`.
    InterfaceList,
    /// `CK_RV f(name, version, CK_INTERFACE_PTR_PTR, flags)`.
    Interface,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRegistry {
    entries: Vec<(String, HookAbi)>,
}

const BUILTIN: [(&str, HookAbi); 5] = [
    ("C_GetFunctionList", HookAbi::FunctionList),
    ("C_GetInterfaceList", HookAbi::InterfaceList),
    ("C_GetInterface", HookAbi::Interface),
    ("NSC_GetFunctionList", HookAbi::FunctionList),
    ("FC_GetFunctionList", HookAbi::FunctionList),
];

impl HookRegistry {
    /// The five built-ins (spec §2): C_GetFunctionList, C_GetInterfaceList,
    /// C_GetInterface, NSC_GetFunctionList, FC_GetFunctionList.
    pub fn builtin() -> Self {
        Self {
            entries: BUILTIN
                .iter()
                .map(|(name, abi)| ((*name).to_string(), *abi))
                .collect(),
        }
    }

    /// `NAME`, `NAME:functionlist`, `NAME:interfacelist`, `NAME:interface`.
    /// Default ABI is `functionlist`. Duplicate names replace the earlier ABI.
    pub fn add_spec(&mut self, spec: &str) -> Result<(), String> {
        let mut parts = spec.split(':');
        let name = parts.next().unwrap_or_default();
        let abi = match parts.next() {
            None => HookAbi::FunctionList,
            Some("functionlist") => HookAbi::FunctionList,
            Some("interfacelist") => HookAbi::InterfaceList,
            Some("interface") => HookAbi::Interface,
            Some(other) => {
                return Err(format!(
                    "unknown hook ABI {other:?}; expected functionlist, interfacelist or interface"
                ));
            }
        };
        if parts.next().is_some() {
            return Err(format!(
                "hook spec {spec:?} has more than one ':' separator"
            ));
        }
        if name.is_empty() {
            return Err(format!("hook spec {spec:?} has an empty symbol name"));
        }
        if name.bytes().any(|b| b.is_ascii_whitespace() || b == 0) {
            return Err(format!("hook symbol {name:?} contains whitespace or NUL"));
        }
        match self
            .entries
            .iter_mut()
            .find(|(existing, _)| existing == name)
        {
            Some(entry) => entry.1 = abi,
            None => self.entries.push((name.to_string(), abi)),
        }
        Ok(())
    }

    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|(name, _)| name.as_str()).collect()
    }

    pub fn abi(&self, name: &str) -> Option<HookAbi> {
        self.entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, abi)| *abi)
    }

    /// Stable one-based symbol identifier used as the export attach cookie.
    pub fn id(&self, name: &str) -> Option<u32> {
        self.entries
            .iter()
            .position(|(candidate, _)| candidate == name)
            .and_then(|position| u32::try_from(position + 1).ok())
    }

    pub fn by_id(&self, id: u32) -> Option<(&str, HookAbi)> {
        let position = usize::try_from(id.checked_sub(1)?).ok()?;
        self.entries
            .get(position)
            .map(|(name, abi)| (name.as_str(), *abi))
    }

    pub fn export_cookie(&self, name: &str) -> Option<u64> {
        self.id(name).map(u64::from)
    }
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_is_the_five_documented_names() {
        let r = HookRegistry::builtin();
        let mut names = r.names();
        names.sort();
        assert_eq!(
            names,
            vec![
                "C_GetFunctionList",
                "C_GetInterface",
                "C_GetInterfaceList",
                "FC_GetFunctionList",
                "NSC_GetFunctionList",
            ]
        );
        assert_eq!(r.abi("C_GetFunctionList"), Some(HookAbi::FunctionList));
        assert_eq!(r.abi("C_GetInterfaceList"), Some(HookAbi::InterfaceList));
        assert_eq!(r.abi("C_GetInterface"), Some(HookAbi::Interface));
        assert_eq!(r.abi("NSC_GetFunctionList"), Some(HookAbi::FunctionList));
        assert_eq!(r.abi("nope"), None);
    }

    #[test]
    fn hook_symbol_specs_default_to_functionlist_and_accept_every_abi() {
        let mut r = HookRegistry::builtin();
        r.add_spec("V_GetTable").unwrap();
        assert_eq!(r.abi("V_GetTable"), Some(HookAbi::FunctionList));
        r.add_spec("V_List:interfacelist").unwrap();
        assert_eq!(r.abi("V_List"), Some(HookAbi::InterfaceList));
        r.add_spec("V_One:interface").unwrap();
        assert_eq!(r.abi("V_One"), Some(HookAbi::Interface));
        // A repeat replaces the ABI rather than duplicating the name.
        r.add_spec("V_GetTable:interface").unwrap();
        assert_eq!(r.abi("V_GetTable"), Some(HookAbi::Interface));
        assert_eq!(r.names().iter().filter(|n| **n == "V_GetTable").count(), 1);
    }

    #[test]
    fn malformed_hook_specs_are_refused_with_the_reason() {
        let mut r = HookRegistry::builtin();
        for bad in [
            "",
            ":",
            ":interface",
            "V_X:",
            "V_X:bogus",
            "V_X:interface:extra",
        ] {
            let error = r.add_spec(bad).unwrap_err();
            assert!(!error.is_empty(), "{bad:?} must be refused with a reason");
        }
        // A name with a NUL or whitespace could never be an ELF symbol.
        assert!(r.add_spec("has space").is_err());
    }

    /// Mutation caught: rebuilding IDs from the current ABI or vector length
    /// changes an existing export cookie when a duplicate is replaced.
    #[test]
    fn ids_are_one_based_stable_and_duplicates_keep_their_id() {
        let mut r = HookRegistry::builtin();
        for (position, (name, abi)) in BUILTIN.iter().enumerate() {
            let id = (position + 1) as u32;
            assert_eq!(r.id(name), Some(id));
            assert_eq!(r.by_id(id), Some((*name, *abi)));
            assert_eq!(r.export_cookie(name), Some(u64::from(id)));
        }
        assert_eq!(r.by_id(0), None);

        r.add_spec("V_GetTable:interfacelist").unwrap();
        let id = r.id("V_GetTable").unwrap();
        assert_eq!(id, 6);
        r.add_spec("V_GetTable:interface").unwrap();
        assert_eq!(r.id("V_GetTable"), Some(id));
        assert_eq!(r.by_id(id), Some(("V_GetTable", HookAbi::Interface)));

        r.add_spec("V_Other").unwrap();
        assert_eq!(r.id("V_Other"), Some(7));
    }
}
