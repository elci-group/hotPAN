//! Codec and secure-channel properties (DIRECTIVE P1.7): round trips hold,
//! and arbitrary or corrupted input yields errors, never panics or wrong data.

use crate::secure::*;
use crate::*;
use proptest::prelude::*;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn plaintext_codec_round_trips(s in "\\PC{0,2000}") {
        rt().block_on(async {
            let mut buf = Vec::new();
            write_frame(&mut buf, &s).await.unwrap();
            let back: String = read_frame(&mut &buf[..]).await.unwrap();
            assert_eq!(back, s);
        });
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_decoders(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        rt().block_on(async {
            let _ = read_frame::<_, NodeMsg>(&mut &bytes[..]).await;
            let _ = read_frame::<_, ClientMsg>(&mut &bytes[..]).await;
            let _ = read_frame::<_, Hello>(&mut &bytes[..]).await;
        });
        let _ = serde_json::from_slice::<NodeMsg>(&bytes);
        let _ = serde_json::from_slice::<OrchMsg>(&bytes);
    }

    /// Corrupt one byte anywhere in a sealed frame: the receiver errors.
    /// It never panics and never yields altered plaintext.
    #[test]
    fn secure_channel_rejects_any_corruption(
        msg in "\\PC{1,3000}",
        pos in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        rt().block_on(async {
            let (a, b) = tokio::io::duplex(1 << 16);
            let (ar, aw) = tokio::io::split(a);
            let (br, bw) = tokio::io::split(b);
            let ka = hotpan_seal::Keypair::generate().kex_secret_bytes();
            let kb = hotpan_seal::Keypair::generate().kex_secret_bytes();
            let (x, y) = tokio::join!(initiate(ar, aw, &ka), respond(br, bw, &kb));
            let (_ar, aw, _) = x.unwrap();
            let (br, _bw, _) = y.unwrap();
            let mut tap = aw.tap();
            tap.send(&msg).await.unwrap();
            let mut wire = tap.into_inner();
            let i = pos.index(wire.len());
            wire[i] ^= flip;
            let mut r = br.reader_over(&wire[..]);
            if let Ok(got) = r.recv::<String>().await {
                panic!("corruption at byte {i} accepted, got {} chars", got.len());
            }
        });
    }
}
