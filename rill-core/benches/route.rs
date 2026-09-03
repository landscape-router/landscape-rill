//! L1 微基准：路由引擎在 dn42 表规模下的 LPM 查找与注入（ROUTE_ENGINE §9 线性扫描的
//! 量化证据——dn42 全表 2~4k 条，逐包 lookup 的线性成本是否可接受以此为准）。
//! 复跑：`taskset -c 0 cargo bench -p landscape-rill-core -- route`（perf.md §2.1/§2.2）

use std::net::IpAddr;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, Criterion};
use landscape_rill_core::route::{RouteEngine, RouteEntry, RouteSource, RouteVia};

/// 条目 i → 172.(16+i/256).(i%256).0/24（互不重叠，全部落在 172.16/12 私有段）
fn dn42_entry(i: u32) -> RouteEntry {
    RouteEntry {
        prefix: landscape_rill_core::route::Prefix::parse(&format!(
            "172.{}.{}.0/24",
            16 + i / 256,
            i % 256
        ))
        .unwrap(),
        source: RouteSource::Dn42,
        via: RouteVia::Dn42(format!("peer-{}", i % 8)),
        metric: None,
    }
}

fn bench_scale(c: &mut Criterion) {
    for n in [100usize, 1000, 4000] {
        let mut group = c.benchmark_group(format!("lpm_dn42_scale_{n}"));
        group.throughput(criterion::Throughput::Elements(1));

        // 注入吞吐（ Learned 批量收敛的引擎侧成本）
        group.bench_function("insert_all", |b| {
            b.iter_batched(
                RouteEngine::new,
                |mut eng| {
                    for i in 0..n {
                        eng.insert(dn42_entry(i as u32));
                    }
                    eng
                },
                criterion::BatchSize::SmallInput,
            )
        });

        let mut eng = RouteEngine::new();
        for i in 0..n {
            eng.insert(dn42_entry(i as u32));
        }
        // 命中中位位置条目内的主机地址（线性扫描的代表性成本）
        let mid: IpAddr = format!("172.{}.{}.55", 16 + n / 2 / 256, (n / 2) % 256)
            .parse()
            .unwrap();

        group.bench_function("lookup_best_hit", |b| {
            b.iter(|| eng.lookup_best(&mid, &|_| true))
        });
        group.bench_function("lookup_best_miss", |b| {
            b.iter(|| eng.lookup_best(&"10.255.255.255".parse().unwrap(), &|_| true))
        });
        group.finish();
    }

    // 注入 4000 条的墙钟耗时（一次性收敛成本的粗量级，info 级）
    let t = Instant::now();
    let mut eng = RouteEngine::new();
    for i in 0..4000 {
        eng.insert(dn42_entry(i as u32));
    }
    let _ = eng.lookup_best(&"172.20.1.1".parse().unwrap(), &|_| true);
    println!("dn42 scale: 4000 inserts + 1 lookup in {:?}", t.elapsed());
}

criterion_group!(benches, bench_scale);
criterion_main!(benches);
