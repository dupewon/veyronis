<div align="center">

# ◈ CONTRIBUTING TO VEYRONIS ◈

```text
 ██████╗ ██████╗ ███╗   ██╗████████╗██████╗ ██╗██████╗ ██╗   ██╗████████╗███████╗
██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██║██╔══██╗██║   ██║╚══██╔══╝██╔════╝
██║     ██║   ██║██╔██╗ ██║   ██║   ██████╔╝██║██████╔╝██║   ██║   ██║   █████╗  
██║     ██║   ██║██║╚██╗██║   ██║   ██╔══██╗██║██╔══██╗██║   ██║   ██║   ██╔══╝  
╚██████╗╚██████╔╝██║ ╚████║   ██║   ██║  ██║██║██████╔╝╚██████╔╝   ██║   ███████╗
 ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝    ╚═╝   ╚══════╝
```

**Open Source Security Engineering • AGPL-3.0 Integrity • Standards of Excellence**

</div>

---

# 🤝 1. Code Standards & Engineering Guidelines

1. **Memory Safety First:** 100% Safe Rust across all parsing and serialization logic.
2. **Deterministic Code Formatting:** All code must pass `cargo fmt --check` without discrepancies.
3. **Zero Clippy Warnings:** All targets must compile cleanly with `cargo clippy --workspace --all-targets -- -D warnings`.
4. **Comprehensive Unit Tests:** Every new parser feature, detection rule, or cryptographic routine must include isolated unit and integration tests.

---

# 🚀 2. Submitting a Pull Request (PR)

```bash
# 1. Create a feature branch
git checkout -b feature/kernel-ebpf-collector

# 2. Verify formatting and linting
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings

# 3. Run complete test suite across 25 crates
cargo test --workspace

# 4. Commit and push
git commit -m "feat(collector): implement native eBPF ring buffer collector"
git push origin feature/kernel-ebpf-collector
```

---

# 📜 3. Developer Certificate of Origin & Licensing

All contributions are subject to the **GNU Affero General Public License v3.0 (AGPL-3.0)**. By submitting a pull request, you certify that the code is your original work and licensed under the project's AGPL-3.0 license.
