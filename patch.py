#!/usr/bin/env python3
from pathlib import Path
import sys

MARKER = "// ShawnCore global entropy consumer gate hardening"


def repo_root() -> Path:
    here = Path.cwd().resolve()
    candidates = [here, Path(__file__).resolve().parent, Path('/tmp/shawn/ShawnCore-Libraries-main')]
    for base in list(candidates):
        candidates.extend(base.parents)
    for base in candidates:
        if (base / 'Cargo.toml').is_file() and (base / 'shawncore-pq-crypto' / 'src' / 'entropy_pool.rs').is_file():
            return base
    raise RuntimeError('Could not locate ShawnCore repository root')


def replace_once(text: str, old: str, new: str, label: str) -> tuple[str, bool]:
    n = text.count(old)
    if n == 0:
        return text, False
    if n != 1:
        raise RuntimeError(f'{label}: expected 1 match, found {n}')
    return text.replace(old, new), True


def main() -> int:
    root = repo_root()
    path = root / 'shawncore-pq-crypto' / 'src' / 'entropy_pool.rs'
    text = path.read_text(encoding='utf-8')
    changed = 0

    # Publish one process-wide consumer gate immediately next to the global queue.
    anchor = '''/// Global asynchronous entropy queue fed by the host OS.\npub static GLOBAL_ENTROPY_QUEUE: EntropyQueue = EntropyQueue::new();\n'''
    replacement = '''/// Global asynchronous entropy queue fed by the host OS.\npub static GLOBAL_ENTROPY_QUEUE: EntropyQueue = EntropyQueue::new();\n\n'''
    replacement += '''/// Process-wide gate protecting the single-consumer side of `GLOBAL_ENTROPY_QUEUE`.\n///\n/// `EntropyPool` instances can be constructed independently, but the queue they\n/// consume is global and SPSC. Therefore its consumer ownership must also be\n/// global; a per-instance `EntropyPool::mixing` flag is insufficient.\nstatic GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE: AtomicBool = AtomicBool::new(false);\n'''
    if 'GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE' not in text:
        text, did = replace_once(text, anchor, replacement, 'global consumer gate')
        changed += int(did)

    # Replace the per-instance gate used by mix_entropy with the process-wide gate.
    old = '''        // GLOBAL_ENTROPY_QUEUE is SPSC. Serialize its consumer side without\n        // putting the expensive SHA-384 work back inside CryptoSpinlock.\n        if self\n            .mixing\n            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)\n            .is_err()\n        {\n            return;\n        }\n\n        let _operation_guard = EntropyOperationGuard(&self.mixing);\n'''
    new = '''        // GLOBAL_ENTROPY_QUEUE is SPSC. Its consumer gate must therefore be\n        // process-wide rather than per-EntropyPool: multiple independent pool\n        // instances can otherwise enter this function concurrently.\n        if GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE\n            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)\n            .is_err()\n        {\n            return;\n        }\n\n        let _operation_guard = EntropyOperationGuard(&GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE);\n'''
    if old in text:
        text, did = replace_once(text, old, new, 'mix_entropy consumer gate')
        changed += int(did)
    elif 'EntropyOperationGuard(&GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE)' not in text:
        raise RuntimeError('mix_entropy consumer gate: expected unpatched or already-patched form')

    # Make the existing concurrent-mixer test exercise the global gate, not an instance flag.
    old_test = '''        assert!(REENTRY_TEST_POOL\n            .mixing\n            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)\n            .is_ok());\n\n        REENTRY_TEST_POOL.mix_entropy();\n        assert!(REENTRY_TEST_POOL.mixing.load(Ordering::Acquire));\n\n        REENTRY_TEST_POOL.mixing.store(false, Ordering::Release);\n'''
    new_test = '''        assert!(GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE\n            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)\n            .is_ok());\n\n        REENTRY_TEST_POOL.mix_entropy();\n        assert!(GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE.load(Ordering::Acquire));\n\n        GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE.store(false, Ordering::Release);\n'''
    if old_test in text:
        text, did = replace_once(text, old_test, new_test, 'global-gate regression')
        changed += int(did)

    # Add an explicit multi-pool regression test once, after the concurrent mixer test.
    anchor_test = '''    #[test]\n    fn extract_reports_busy_without_waiting_for_an_active_mixer() {\n'''
    multi_test = '''    #[test]\n    fn independent_pools_share_one_global_queue_consumer_gate() {\n        let _entropy_test_guard = ENTROPY_TEST_SERIAL_LOCK\n            .lock()\n            .expect("entropy test lock poisoned");\n        let pool_a = EntropyPool::new();\n        let pool_b = EntropyPool::new();\n\n        assert!(GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE\n            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)\n            .is_ok());\n\n        pool_a.mix_entropy();\n        pool_b.mix_entropy();\n        assert!(GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE.load(Ordering::Acquire));\n\n        GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE.store(false, Ordering::Release);\n    }\n\n'''
    if 'fn independent_pools_share_one_global_queue_consumer_gate()' not in text:
        text, did = replace_once(text, anchor_test, multi_test + anchor_test, 'multi-pool regression')
        changed += int(did)

    # Clarify the public field comment so the per-instance flag's remaining role is not confused with queue ownership.
    old_comment = '''    /// Serializes callers that drain the single-consumer global entropy queue.\n    mixing: AtomicBool,\n'''
    new_comment = '''    /// Serializes mutating operations on this pool instance.\n    ///\n    /// This does not own the global queue consumer; that role is protected by\n    /// `GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE`.\n    mixing: AtomicBool,\n'''
    if old_comment in text:
        text, did = replace_once(text, old_comment, new_comment, 'per-instance mixing comment')
        changed += int(did)

    # Add architecture contract near the entropy section if absent.
    arch = root / 'ARCHITECTURE.md'
    if arch.exists():
        at = arch.read_text(encoding='utf-8')
        marker_text = '### Global entropy queue consumer ownership'
        if marker_text not in at:
            insert_before = '## RTOS primitives'
            block = '''### Global entropy queue consumer ownership\n\n`GLOBAL_ENTROPY_QUEUE` is a single-producer/single-consumer queue with a process-wide consumer. `EntropyPool` instances are independently constructible, so queue-consumer ownership is protected by a single global gate rather than an instance-local flag. Pool-local operation state remains separate from global queue ownership.\n\n'''
            if insert_before in at:
                at = at.replace(insert_before, block + insert_before, 1)
                arch.write_text(at, encoding='utf-8')
                changed += 1

    path.write_text(text, encoding='utf-8')

    # Static verification of the intended state.
    text = path.read_text(encoding='utf-8')
    checks = [
        ('global gate declaration', 'static GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE: AtomicBool = AtomicBool::new(false);' in text),
        ('mix_entropy uses global gate', 'EntropyOperationGuard(&GLOBAL_ENTROPY_QUEUE_CONSUMER_GATE)' in text),
        ('multi-pool regression', 'fn independent_pools_share_one_global_queue_consumer_gate()' in text),
        ('per-instance comment clarified', 'This does not own the global queue consumer' in text),
    ]
    failed = [name for name, ok in checks if not ok]
    if failed:
        raise RuntimeError('verification failed: ' + ', '.join(failed))

    print('ShawnCore global entropy consumer gate patch')
    print(f'Repository: {root}')
    print(f'Applied changes: {changed}')
    print('Verified: process-wide SPSC consumer gate and multi-pool regression present')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        raise SystemExit(1)
