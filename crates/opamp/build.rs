// The OpAMP protobuf types, generated from the vendored, pinned schema (ADR-0011).
//
// Nothing else happens here, and nothing here needs more than this package: the schema ships
// inside it, protox compiles it without a system `protoc`, and the output goes only to `OUT_DIR`.
// That is what lets the crate build wherever it is fetched to (ADR-0010).

/// The Protocol Baseline. The single place the proto path derives from, which is what kept
/// upstream's relocation of the files (`proto/` to `proto/opamp/v1/`, adopted with `v0.19.0`) a
/// change to this file alone — docs/CONFORMANCE.md requires it stay that way. It is also what
/// `opamp::BASELINE` reports, and the crate's own version is checked against it.
const BASELINE: &str = "v0.20.0";

fn main() {
    println!("cargo:rustc-env=OPAMP_BASELINE={BASELINE}");
    generate_protobuf_types();
}

fn generate_protobuf_types() {
    // The include root: `opamp.proto` imports its sibling as `opamp/v1/anyvalue.proto`, so the
    // import only resolves when the root is the directory *above* `opamp/v1`, never the directory
    // holding the files.
    let root = format!("proto/{BASELINE}");
    let files = [
        format!("{root}/opamp/v1/opamp.proto"),
        format!("{root}/opamp/v1/anyvalue.proto"),
    ];

    let descriptors = protox::compile(&files, [&root]).expect("compile OpAMP protobuf schema");
    prost_build::Config::new()
        .compile_fds(descriptors)
        .expect("generate Rust types from the OpAMP schema");

    for file in files {
        println!("cargo:rerun-if-changed={file}");
    }
}
