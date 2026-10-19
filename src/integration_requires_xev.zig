comptime {
    @compileError(
        "tls_xev is opt-in; pass .xev = true to b.dependency(\"tls\", ...)",
    );
}
