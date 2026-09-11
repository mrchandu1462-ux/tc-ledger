"""tc-ledger: A cryptographic evidence layer for Technocore room exports."""

from .ledger import (
    # Core exceptions
    VerificationError,
    MalformedRecord,
    InvalidSignature,
    UnsupportedKeyType,
    BadSignatureError,
    # Data structures
    VerificationResult,
    EvidenceLeafMapping,
    ExportEvidenceIndex,
    # Cryptographic primitives
    leaf_hash,
    node_hash,
    export_leaf_hash,
    evidence_commitment,
    export_merkle_root,
    export_merkle_proof,
    expected_proof_directions,
    public_key_from_did,
    # Export and record verification
    verify_signed_record,
    verify_export,
    classify_export_lines,
    map_evidence_to_export,
    find_duplicate_evidence_ids,
    # Commitment artifacts
    build_commitment_artifact,
    write_commitment_artifact,
    verify_commitment_artifact,
    # Inclusion proof artifacts
    build_inclusion_proof_artifact,
    write_inclusion_proof_artifact,
    verify_export_inclusion_proof,
    verify_inclusion_proof_artifact,
    # C7 Consistency proof artifacts
    consistency_proof,
    verify_consistency_proof,
    build_consistency_proof_artifact,
    write_consistency_proof_artifact,
    verify_consistency_proof_artifact,
    # CLI entry point
    main,
)

__version__ = "0.3.0"

__all__ = [
    "__version__",
    "VerificationError",
    "MalformedRecord",
    "InvalidSignature",
    "UnsupportedKeyType",
    "BadSignatureError",
    "VerificationResult",
    "EvidenceLeafMapping",
    "ExportEvidenceIndex",
    "leaf_hash",
    "node_hash",
    "export_leaf_hash",
    "evidence_commitment",
    "export_merkle_root",
    "export_merkle_proof",
    "expected_proof_directions",
    "public_key_from_did",
    "verify_signed_record",
    "verify_export",
    "classify_export_lines",
    "map_evidence_to_export",
    "find_duplicate_evidence_ids",
    "build_commitment_artifact",
    "write_commitment_artifact",
    "verify_commitment_artifact",
    "build_inclusion_proof_artifact",
    "write_inclusion_proof_artifact",
    "verify_export_inclusion_proof",
    "verify_inclusion_proof_artifact",
    "consistency_proof",
    "verify_consistency_proof",
    "build_consistency_proof_artifact",
    "write_consistency_proof_artifact",
    "verify_consistency_proof_artifact",
    "main",
]
