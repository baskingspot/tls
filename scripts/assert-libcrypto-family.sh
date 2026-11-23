#!/usr/bin/env bash
set -euo pipefail

expected="${1:-}"
case "${expected}" in
  openssl|aws-lc|boringssl) ;;
  *)
    echo "usage: $0 openssl|aws-lc|boringssl" >&2
    exit 2
    ;;
esac

# The aws-lc package may ship only suffixed modules and libraries (#223):
# libcrypto-awslc.pc, libssl-awslc.pc, headers under include/aws-lc. Its
# product module is `aws-lc` under every spelling, so ask for that one.
case "${expected}" in
  aws-lc) pkg_config_module=aws-lc ;;
  *) pkg_config_module=libcrypto ;;
esac

include_dir="$(pkg-config --variable=includedir "${pkg_config_module}")"
macros="$(printf '#include <openssl/opensslv.h>\n' | zig cc -I"${include_dir}" -dM -E -x c -)"
has_aws_lc=false
has_boringssl=false
if grep -q '^#define OPENSSL_IS_AWSLC\([[:space:]]\|$\)' <<<"${macros}"; then
  has_aws_lc=true
fi
if grep -q '^#define OPENSSL_IS_BORINGSSL\([[:space:]]\|$\)' <<<"${macros}"; then
  has_boringssl=true
fi

case "${expected}" in
  openssl)
    if ${has_aws_lc} || ${has_boringssl}; then
      echo "expected OpenSSL headers at ${include_dir}" >&2
      exit 1
    fi
    ;;
  aws-lc)
    if ! ${has_aws_lc} || ${has_boringssl}; then
      echo "expected AWS-LC headers at ${include_dir}" >&2
      exit 1
    fi
    ;;
  boringssl)
    if ${has_aws_lc} || ! ${has_boringssl}; then
      echo "expected BoringSSL headers at ${include_dir}" >&2
      exit 1
    fi
    ;;
esac

printf 'libcrypto family: %s (%s)\n' "${expected}" "${include_dir}"
