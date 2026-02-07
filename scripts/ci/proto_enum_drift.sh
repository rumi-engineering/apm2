#!/usr/bin/env bash
# CI drift guard: detect protocol enum drift between .proto and Rust source (TCK-00409)
#
# Checks that enum variants defined in .proto files match those in the
# generated Rust code. This catches cases where a proto enum is updated
# but the generated code is not regenerated, or vice versa.
#
# The canonical source of truth is the .proto file; this script verifies
# the generated Rust file (apm2.daemon.v1.rs) is in sync.
#
# Exit codes:
#   0 - No enum drift detected
#   1 - Enum drift detected
#   2 - Script error
#
# Usage:
#   ./scripts/ci/proto_enum_drift.sh

set -euo pipefail

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

log_error() { echo -e "${RED}ERROR:${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}WARN:${NC} $*" >&2; }
log_info() { echo -e "${GREEN}INFO:${NC} $*"; }

VIOLATIONS=0

REPO_ROOT="$(git rev-parse --show-toplevel)"
PROTO_FILE="${REPO_ROOT}/proto/apm2d_runtime_v1.proto"
GENERATED_RS="${REPO_ROOT}/crates/apm2-daemon/src/protocol/apm2.daemon.v1.rs"

log_info "=== Proto Enum Drift Detection (TCK-00409) ==="
echo

if [[ ! -f "$PROTO_FILE" ]]; then
    log_error "Proto file not found: $PROTO_FILE"
    exit 2
fi

if [[ ! -f "$GENERATED_RS" ]]; then
    log_error "Generated Rust file not found: $GENERATED_RS"
    exit 2
fi

# Extract enum variant NAMES from a .proto file.
# Outputs lines of the form: EnumName=VARIANT_A,VARIANT_B,...
extract_proto_enum_names() {
    local file="$1"
    local current_enum=""
    local variants=""

    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*enum[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\{ ]]; then
            current_enum="${BASH_REMATCH[1]}"
            variants=""
            continue
        fi
        if [[ -n "$current_enum" ]] && [[ "$line" =~ ^[[:space:]]*\} ]]; then
            echo "${current_enum}=${variants}"
            current_enum=""
            continue
        fi
        if [[ -n "$current_enum" ]] && [[ "$line" =~ ^[[:space:]]*([A-Z_][A-Z0-9_]*)[[:space:]]*=[[:space:]]*[0-9]+ ]]; then
            local vname="${BASH_REMATCH[1]}"
            if [[ -n "$variants" ]]; then
                variants="${variants},${vname}"
            else
                variants="${vname}"
            fi
        fi
    done < "$file"
}

# Extract enum variant NAME=DISCRIMINANT pairs from a .proto file.
# Outputs lines of the form: EnumName=VARIANT_A:0,VARIANT_B:1,...
extract_proto_enum_discriminants() {
    local file="$1"
    local current_enum=""
    local pairs=""

    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*enum[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*\{ ]]; then
            current_enum="${BASH_REMATCH[1]}"
            pairs=""
            continue
        fi
        if [[ -n "$current_enum" ]] && [[ "$line" =~ ^[[:space:]]*\} ]]; then
            echo "${current_enum}=${pairs}"
            current_enum=""
            continue
        fi
        if [[ -n "$current_enum" ]] && [[ "$line" =~ ^[[:space:]]*([A-Z_][A-Z0-9_]*)[[:space:]]*=[[:space:]]*([0-9]+) ]]; then
            local vname="${BASH_REMATCH[1]}"
            local vnum="${BASH_REMATCH[2]}"
            if [[ -n "$pairs" ]]; then
                pairs="${pairs},${vname}:${vnum}"
            else
                pairs="${vname}:${vnum}"
            fi
        fi
    done < "$file"
}

# Extract variant names from the Rust as_str_name() impl for a given enum.
# prost generates:
#   impl EnumName {
#     pub fn as_str_name(&self) -> &'static str {
#       match self {
#         Self::Variant => "PROTO_NAME",
#         ...
#       }
#     }
# We extract the quoted "PROTO_NAME" strings, which are the canonical proto names.
extract_rs_enum_names() {
    local file="$1"
    local target_enum="$2"
    local in_impl=0
    local in_as_str=0
    local names=""
    local brace_depth=0

    while IFS= read -r line; do
        # Find: impl EnumName {
        if [[ $in_impl -eq 0 ]] && [[ "$line" =~ ^impl\ ${target_enum}\ \{ ]]; then
            in_impl=1
            brace_depth=1
            continue
        fi
        if [[ $in_impl -eq 1 ]]; then
            # Track brace depth
            local opens="${line//[^\{]/}"
            local closes="${line//[^\}]/}"
            brace_depth=$((brace_depth + ${#opens} - ${#closes}))

            # Detect as_str_name method
            if [[ "$line" =~ pub\ fn\ as_str_name ]]; then
                in_as_str=1
                continue
            fi
            # In as_str_name, extract Self::Variant => "PROTO_NAME"
            if [[ $in_as_str -eq 1 ]]; then
                if [[ "$line" =~ Self::[A-Za-z0-9_]+[[:space:]]*=\>[[:space:]]*\"([A-Z_][A-Z0-9_]*)\" ]]; then
                    local vname="${BASH_REMATCH[1]}"
                    if [[ -n "$names" ]]; then
                        names="${names},${vname}"
                    else
                        names="${vname}"
                    fi
                fi
                # End of as_str_name: next pub fn or closing brace
                if [[ "$line" =~ ^[[:space:]]*\} ]] && [[ "$line" != *"=>"* ]]; then
                    in_as_str=0
                fi
            fi

            if [[ $brace_depth -le 0 ]]; then
                break
            fi
        fi
    done < "$file"
    echo "$names"
}

# Extract enum variant NAME:DISCRIMINANT pairs from generated Rust code.
# prost generates:
#   pub enum EnumName {
#     VariantCamelCase = 0,
#     ...
#   }
#   impl EnumName {
#     pub fn as_str_name(&self) -> &'static str {
#       match self {
#         Self::VariantCamelCase => "PROTO_NAME",
#       }
#     }
#   }
# We join the two to produce PROTO_NAME:discriminant pairs.
extract_rs_enum_discriminants() {
    local file="$1"
    local target_enum="$2"

    # Step 1: Extract CamelCase=discriminant from the pub enum block
    declare -A camel_to_disc
    local in_enum=0
    local brace_depth=0
    while IFS= read -r line; do
        if [[ $in_enum -eq 0 ]] && [[ "$line" =~ ^pub\ enum\ ${target_enum}\ \{ ]]; then
            in_enum=1
            brace_depth=1
            continue
        fi
        if [[ $in_enum -eq 1 ]]; then
            local opens="${line//[^\{]/}"
            local closes="${line//[^\}]/}"
            brace_depth=$((brace_depth + ${#opens} - ${#closes}))
            if [[ "$line" =~ ^[[:space:]]*([A-Za-z][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*([0-9]+) ]]; then
                camel_to_disc["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
            fi
            if [[ $brace_depth -le 0 ]]; then
                break
            fi
        fi
    done < "$file"

    # Step 2: Extract CamelCase => "PROTO_NAME" from as_str_name
    declare -A camel_to_proto
    local in_impl=0
    local in_as_str=0
    brace_depth=0
    while IFS= read -r line; do
        if [[ $in_impl -eq 0 ]] && [[ "$line" =~ ^impl\ ${target_enum}\ \{ ]]; then
            in_impl=1
            brace_depth=1
            continue
        fi
        if [[ $in_impl -eq 1 ]]; then
            local opens="${line//[^\{]/}"
            local closes="${line//[^\}]/}"
            brace_depth=$((brace_depth + ${#opens} - ${#closes}))
            if [[ "$line" =~ pub\ fn\ as_str_name ]]; then
                in_as_str=1
                continue
            fi
            if [[ $in_as_str -eq 1 ]]; then
                if [[ "$line" =~ Self::([A-Za-z0-9_]+)[[:space:]]*=\>[[:space:]]*\"([A-Z_][A-Z0-9_]*)\" ]]; then
                    camel_to_proto["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
                fi
                if [[ "$line" =~ ^[[:space:]]*\} ]] && [[ "$line" != *"=>"* ]]; then
                    in_as_str=0
                fi
            fi
            if [[ $brace_depth -le 0 ]]; then
                break
            fi
        fi
    done < "$file"

    # Step 3: Join on CamelCase key to produce PROTO_NAME:discriminant
    local pairs=""
    for camel in "${!camel_to_disc[@]}"; do
        local proto_name="${camel_to_proto[$camel]:-}"
        local disc="${camel_to_disc[$camel]}"
        if [[ -n "$proto_name" ]]; then
            if [[ -n "$pairs" ]]; then
                pairs="${pairs},${proto_name}:${disc}"
            else
                pairs="${proto_name}:${disc}"
            fi
        fi
    done
    echo "$pairs"
}

log_info "Comparing enum variant names..."

proto_enums=$(extract_proto_enum_names "$PROTO_FILE")

for entry in $proto_enums; do
    enum_name="${entry%%=*}"
    proto_names_csv="${entry##*=}"

    rs_names_csv=$(extract_rs_enum_names "$GENERATED_RS" "$enum_name")

    if [[ -z "$rs_names_csv" ]]; then
        log_error "Enum ${enum_name} defined in proto but not found in generated Rust code (rs_count=0)"
        log_error "  Proto: ${PROTO_FILE}"
        log_error "  Rust:  ${GENERATED_RS}"
        log_error "  Run 'cargo build -p apm2-daemon' to regenerate."
        VIOLATIONS=1
        continue
    fi

    # Sort both name sets for comparison (use ${var//,/$'\n'} to avoid tr portability issues)
    proto_sorted=$(printf '%s\n' ${proto_names_csv//,/ } | sort)
    rs_sorted=$(printf '%s\n' ${rs_names_csv//,/ } | sort)

    # Count actual non-empty variants (guard against empty-string false-OK)
    rs_count=$(printf '%s\n' ${rs_names_csv//,/ } | grep -c '[A-Z]' || true)
    proto_count=$(printf '%s\n' ${proto_names_csv//,/ } | grep -c '[A-Z]' || true)

    if [[ "$rs_count" -eq 0 ]]; then
        log_error "Enum ${enum_name}: generated Rust has 0 parseable variants (rs_count=0) — hard violation"
        log_error "  Proto defines ${proto_count} variants but Rust has none."
        log_error "  Run 'cargo build -p apm2-daemon' to regenerate."
        VIOLATIONS=1
        continue
    fi

    if [[ "$proto_sorted" != "$rs_sorted" ]]; then
        # Compute set differences for a helpful error message
        only_in_proto=$(comm -23 <(echo "$proto_sorted") <(echo "$rs_sorted"))
        only_in_rust=$(comm -13 <(echo "$proto_sorted") <(echo "$rs_sorted"))
        log_error "Enum drift: ${enum_name} variant names differ between proto and generated Rust"
        if [[ -n "$only_in_proto" ]]; then
            log_error "  Only in proto: $(echo "$only_in_proto" | paste -sd' ')"
        fi
        if [[ -n "$only_in_rust" ]]; then
            log_error "  Only in Rust:  $(echo "$only_in_rust" | paste -sd' ')"
        fi
        log_error "  Proto: ${PROTO_FILE}"
        log_error "  Rust:  ${GENERATED_RS}"
        log_error "  Run 'cargo build -p apm2-daemon' to regenerate."
        VIOLATIONS=1
    else
        log_info "  ${enum_name}: ${proto_count} variants (OK)"
    fi
done

# Check 2: Compare enum discriminant (numeric) values.
log_info "Comparing enum discriminant values..."

proto_disc_enums=$(extract_proto_enum_discriminants "$PROTO_FILE")

for entry in $proto_disc_enums; do
    enum_name="${entry%%=*}"
    proto_pairs_csv="${entry##*=}"

    rs_pairs_csv=$(extract_rs_enum_discriminants "$GENERATED_RS" "$enum_name")

    if [[ -z "$rs_pairs_csv" ]]; then
        # Treat missing Rust discriminants as a hard violation (not just a warning).
        # The name check above may have caught this, but we enforce here too for
        # fail-closed semantics — never silently skip a missing enum.
        log_error "Enum ${enum_name}: no Rust discriminants found (rs_count=0) — hard violation"
        log_error "  Run 'cargo build -p apm2-daemon' to regenerate."
        VIOLATIONS=1
        continue
    fi

    # Build sorted "NAME:DISC" lines for comparison
    proto_disc_sorted=$(printf '%s\n' ${proto_pairs_csv//,/ } | sort)
    rs_disc_sorted=$(printf '%s\n' ${rs_pairs_csv//,/ } | sort)

    if [[ "$proto_disc_sorted" != "$rs_disc_sorted" ]]; then
        # Find which pairs differ
        disc_only_proto=$(comm -23 <(echo "$proto_disc_sorted") <(echo "$rs_disc_sorted"))
        disc_only_rust=$(comm -13 <(echo "$proto_disc_sorted") <(echo "$rs_disc_sorted"))
        log_error "Enum discriminant drift: ${enum_name} numeric values differ between proto and Rust"
        if [[ -n "$disc_only_proto" ]]; then
            log_error "  Only in proto: $(echo "$disc_only_proto" | paste -sd' ')"
        fi
        if [[ -n "$disc_only_rust" ]]; then
            log_error "  Only in Rust:  $(echo "$disc_only_rust" | paste -sd' ')"
        fi
        log_error "  Proto: ${PROTO_FILE}"
        log_error "  Rust:  ${GENERATED_RS}"
        log_error "  Run 'cargo build -p apm2-daemon' to regenerate."
        VIOLATIONS=1
    else
        disc_count=$(printf '%s\n' ${proto_pairs_csv//,/ } | grep -c '[A-Z]' || true)
        log_info "  ${enum_name}: ${disc_count} discriminants (OK)"
    fi
done

echo
if [[ $VIOLATIONS -eq 1 ]]; then
    log_error "=== FAILED: Proto/Rust enum drift detected ==="
    log_error "Run 'cargo build -p apm2-daemon' to regenerate proto code."
    exit 1
else
    log_info "=== PASSED: No proto/Rust enum drift detected ==="
    exit 0
fi
