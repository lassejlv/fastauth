use fastauth_core::memory::MemoryAdapter;
use fastauth_core::testing::{run_adapter_conformance, run_adapter_conformance_renamed};

#[tokio::test]
async fn memory_adapter_passes_the_conformance_suite() {
    run_adapter_conformance(async || MemoryAdapter::new()).await;
}

#[tokio::test]
async fn memory_adapter_passes_the_conformance_suite_with_renamed_columns() {
    run_adapter_conformance_renamed(async || MemoryAdapter::new()).await;
}
