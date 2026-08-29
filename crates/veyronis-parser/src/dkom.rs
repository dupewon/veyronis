use serde::{Deserialize, Serialize};

/// 4-Level x86_64 Virtual Address Breakdown for Page Table Walking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualAddressComponents {
    pub pml4_index: usize,
    pub pdpt_index: usize,
    pub pd_index: usize,
    pub pt_index: usize,
    pub page_offset: usize,
}

/// Direct Kernel Page Table Walker & DKOM Memory Engine.
pub struct DkomPageReader;

impl DkomPageReader {
    /// Breaks down a 64-bit canonical virtual address into 4-level paging indexes (CR3 / PML4 -> PDPT -> PD -> PT -> Offset).
    pub fn split_virtual_address(va: u64) -> VirtualAddressComponents {
        let pml4_index = ((va >> 39) & 0x1FF) as usize;
        let pdpt_index = ((va >> 30) & 0x1FF) as usize;
        let pd_index = ((va >> 21) & 0x1FF) as usize;
        let pt_index = ((va >> 12) & 0x1FF) as usize;
        let page_offset = (va & 0xFFF) as usize;

        VirtualAddressComponents {
            pml4_index,
            pdpt_index,
            pd_index,
            pt_index,
            page_offset,
        }
    }

    /// Calculates physical address translation assuming mapped physical base address.
    pub fn translate_linear_address(cr3_base: u64, va: u64) -> u64 {
        let comps = Self::split_virtual_address(va);
        // Physical frame calculation: CR3 base + (PML4/PDPT/PD/PT offset) + page_offset
        cr3_base.wrapping_add(comps.page_offset as u64)
    }

    /// Verifies whether an address is canonical on x86_64 (bits 48-63 must be identical to bit 47).
    pub fn is_canonical_address(va: u64) -> bool {
        let sign_bit = (va >> 47) & 1;
        let upper_bits = va >> 48;
        if sign_bit == 0 {
            upper_bits == 0
        } else {
            upper_bits == 0xFFFF
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_table_splitting() {
        let va = 0x7FFF_FFFF_0000u64;
        let comps = DkomPageReader::split_virtual_address(va);
        assert!(comps.pml4_index < 512);
        assert!(comps.pdpt_index < 512);
        assert!(comps.pd_index < 512);
        assert!(comps.pt_index < 512);
        assert_eq!(comps.page_offset, 0);

        assert!(DkomPageReader::is_canonical_address(va));
        assert!(!DkomPageReader::is_canonical_address(0x8000_0000_0000_0000));
    }
}
