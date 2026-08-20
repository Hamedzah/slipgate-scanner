# Scoring Rationale

The composite score (0-100) blends five sub-scores. Default weights:

| Factor      | Weight | Rationale |
|-------------|--------|-----------|
| Latency     | 25%    | Dominant factor for interactive use (chat, browsing). |
| Speed       | 25%    | Matters for media/file transfer; measured via a real 5MB+ download through the tunnel. |
| Stability   | 20%    | Packet/round loss + jitter — a flaky-but-fast proxy is often worse in practice than a stable, moderate one. |
| Geo         | 15%    | Distance from Iran + confirmed non-Iranian ISP exit; an exit inside an Iranian ISP has zero circumvention value. |
| Protocol    | 15%    | Structural/security quality: Reality > VLESS/Trojan+TLS > VMess > Shadowsocks > MTProto (weakest transport security). |

Adjust weights in `.env` (`WEIGHT_LATENCY`, `WEIGHT_SPEED`, `WEIGHT_STABILITY`,
`WEIGHT_GEO`, `WEIGHT_PROTOCOL`) to fit your priorities — they don't need to
sum to exactly 1.0, but scores are most interpretable on a 0-100 scale when
they do.
