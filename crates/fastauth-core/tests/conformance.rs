use fastauth_core::memory::MemoryAdapter;
use fastauth_core::testing::run_adapter_conformance;

#[tokio::test]
async fn memory_adapter_passes_the_conformance_suite() {
    run_adapter_conformance(async || MemoryAdapter::new()).await;
}
