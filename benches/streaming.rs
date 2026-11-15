use criterion::{black_box, criterion_group, criterion_main, Criterion};
use russ::core::{
    streaming::copy_stream, AdaptiveOptimizer, BufferPool, OptimizerConfig, TransferControl,
};
use russ::hardware::HardwareSnapshot;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::Runtime,
};

fn bounded_streaming_throughput(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Tokio runtime");
    let mut profile = HardwareSnapshot::default();
    profile.cpu.logical_cores = 4;
    profile.memory.available_bytes = 512 * 1024 * 1024;
    let optimizer = AdaptiveOptimizer::new(profile, OptimizerConfig::default());
    let pool = BufferPool::new(optimizer.plan()).expect("bounded buffer plan");

    c.bench_function("bounded_stream_copy_8_mib", |benchmark| {
        benchmark.to_async(&runtime).iter(|| async {
            let payload = vec![0x5a_u8; 8 * 1024 * 1024];
            let expected_length = payload.len();
            let (mut source_writer, mut source_reader) = tokio::io::duplex(64 * 1024);
            let source_task = tokio::spawn(async move {
                source_writer.write_all(&payload).await?;
                source_writer.shutdown().await
            });
            let (mut destination_reader, mut destination_writer) = tokio::io::duplex(64 * 1024);
            let destination_task = tokio::spawn(async move {
                let mut received = Vec::new();
                destination_reader.read_to_end(&mut received).await?;
                Ok::<_, std::io::Error>(received.len())
            });

            let stats = copy_stream(
                &mut source_reader,
                &mut destination_writer,
                &pool,
                &TransferControl::default(),
                |_| {},
            )
            .await
            .expect("bounded copy");
            destination_writer
                .shutdown()
                .await
                .expect("close destination");
            source_task
                .await
                .expect("source task")
                .expect("source write");
            let received_length = destination_task
                .await
                .expect("destination task")
                .expect("destination read");
            black_box((stats.bytes_copied, received_length, expected_length));
        });
    });
}

criterion_group!(benches, bounded_streaming_throughput);
criterion_main!(benches);
