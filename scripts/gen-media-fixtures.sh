#!/usr/bin/env bash
# Copyright 2026- Seongwoo Hong. All rights reserved.
#
# Real-content MP4 fixtures for crates/media (the video sidecar's engine,
# commit 39p) — synthetic, deterministic content from ffmpeg's lavfi, one
# file per code path the tests in crates/media/tests/real_content.rs and
# src/indexer.rs exercise (ported from the stream-worker project's
# gen_fixtures.sh). Output: tests/output/fixtures-real/ (git-ignored); the
# tests SKIP when it is missing. BIG=1 adds a > 64 MiB file (the lazy box
# walk) — slow, so off by default.
#
#   bframes        H.264 B-frames → ctts + edit list (CMAF cts shift)
#   regular        plain H.264, moov at end (default ffmpeg layout)
#   faststart      moov at front
#   moovend_heavy  many chunks (stsc multi-run), moov at end
#   hevc           HEVC, hvcC codec string
#   hevc_bframes   HEVC (hev1) with B-frames → hvcC + edit list
#   fragmented     fMP4 (frag_keyframe + empty_moov + default_base_moof)
#   cmaf_dash      fMP4 with sidx/styp boxes between fragments (+ mfra)
#   audio_only     AAC only → audio primary track
#   video_only     no audio track
#   opus / ac3     non-AAC audio sample entries (bare-fourcc codec strings)
#   multi_audio    two audio tracks (only the first is served)
#   long_gop       10-second GOPs → segments longer than the target
#   vfr            variable frame rate → per-sample duration deltas
#   uhd            3840x2160 video-only (resolution attributes)
#   big_lazy       > 64MB (BIG=1 only)
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=tests/output/fixtures-real
mkdir -p "$OUT"

ENC_ARGS=(-c:v libx264 -preset ultrafast -crf 30 -pix_fmt yuv420p)
AUD_ARGS=(-c:a aac -b:a 48k)

if ! command -v ffmpeg >/dev/null; then
  echo "ffmpeg not found — run the real-content gate on a machine with ffmpeg" >&2
  exit 1
fi
FF=(ffmpeg -hide_banner -loglevel error -y)
VID() { echo "testsrc2=size=${2:-320x180}:rate=${3:-24}:duration=$1"; }
AUD() { echo "sine=frequency=$2:sample_rate=${3:-44100}:duration=$1"; }

echo "== bframes.mp4: H.264 + B-frames + AAC (ctts v1 path)"
"${FF[@]}" -f lavfi -i "$(VID 20)" -f lavfi -i "$(AUD 20 440)" "${ENC_ARGS[@]}" -bf 3 -g 48 "${AUD_ARGS[@]}" -shortest "$OUT/bframes.mp4"

echo "== regular.mp4: plain H.264, moov at end (default ffmpeg layout)"
"${FF[@]}" -f lavfi -i "$(VID 10)" -f lavfi -i "$(AUD 10 1000)" "${ENC_ARGS[@]}" -bf 0 -g 24 "${AUD_ARGS[@]}" -shortest "$OUT/regular.mp4"

echo "== fragmented.mp4: fMP4 (frag_keyframe + empty_moov + default_base_moof)"
"${FF[@]}" -f lavfi -i "$(VID 20)" -f lavfi -i "$(AUD 20 500)" "${ENC_ARGS[@]}" -g 24 "${AUD_ARGS[@]}" \
  -movflags +frag_keyframe+empty_moov+default_base_moof -shortest "$OUT/fragmented.mp4"

echo "== cmaf_dash.mp4: fMP4 with sidx boxes between fragments and a trailing mfra"
"${FF[@]}" -f lavfi -i "$(VID 12)" -f lavfi -i "$(AUD 12 500)" "${ENC_ARGS[@]}" -g 24 "${AUD_ARGS[@]}" \
  -movflags +dash+frag_keyframe+empty_moov+default_base_moof -shortest "$OUT/cmaf_dash.mp4"

echo "== hevc.mp4: HEVC/H.265 (hvcC codec path)"
"${FF[@]}" -f lavfi -i "$(VID 8)" -c:v libx265 -preset ultrafast -crf 30 -pix_fmt yuv420p -g 24 -x265-params log-level=error \
  -movflags +faststart "$OUT/hevc.mp4"

echo "== hevc_bframes.mp4: HEVC (hev1) with B-frames + AAC 48k"
"${FF[@]}" -f lavfi -i "$(VID 12)" -f lavfi -i "$(AUD 12 330 48000)" -c:v libx265 -preset ultrafast -crf 30 -pix_fmt yuv420p \
  -x265-params bframes=3:keyint=48:log-level=error "${AUD_ARGS[@]}" -shortest "$OUT/hevc_bframes.mp4"

echo "== moovend_heavy.mp4: many chunks (stsc multi-run), moov at end"
"${FF[@]}" -f lavfi -i "$(VID 30)" -f lavfi -i "$(AUD 30 220)" "${ENC_ARGS[@]}" -g 24 "${AUD_ARGS[@]}" -shortest "$OUT/moovend_heavy.mp4"

echo "== faststart.mp4: moov at front"
"${FF[@]}" -f lavfi -i "$(VID 10)" -f lavfi -i "$(AUD 10 880)" "${ENC_ARGS[@]}" -g 24 "${AUD_ARGS[@]}" -movflags +faststart -shortest "$OUT/faststart.mp4"

echo "== audio_only.mp4: AAC only"
"${FF[@]}" -f lavfi -i "$(AUD 15 440 48000)" -c:a aac -b:a 64k "$OUT/audio_only.mp4"

echo "== video_only.mp4: no audio track"
"${FF[@]}" -f lavfi -i "$(VID 10)" "${ENC_ARGS[@]}" -g 24 "$OUT/video_only.mp4"

echo "== opus.mp4: H.264 + Opus"
"${FF[@]}" -f lavfi -i "$(VID 12)" -f lavfi -i "$(AUD 12 550 48000)" "${ENC_ARGS[@]}" -g 24 -c:a libopus -b:a 48k -strict -2 -shortest "$OUT/opus.mp4"

echo "== ac3.mp4: H.264 + AC-3"
"${FF[@]}" -f lavfi -i "$(VID 12)" -f lavfi -i "$(AUD 12 660 48000)" "${ENC_ARGS[@]}" -g 24 -c:a ac3 -b:a 96k -shortest "$OUT/ac3.mp4"

echo "== multi_audio.mp4: two AAC tracks (eng, deu)"
"${FF[@]}" -f lavfi -i "$(VID 12)" -f lavfi -i "$(AUD 12 440)" -f lavfi -i "$(AUD 12 880)" -map 0:v -map 1:a -map 2:a \
  "${ENC_ARGS[@]}" -g 24 "${AUD_ARGS[@]}" -metadata:s:a:0 language=eng -metadata:s:a:1 language=deu -shortest "$OUT/multi_audio.mp4"

echo "== long_gop.mp4: 10-second GOPs"
"${FF[@]}" -f lavfi -i "$(VID 30)" -f lavfi -i "$(AUD 30 220)" "${ENC_ARGS[@]}" -g 240 -keyint_min 240 -sc_threshold 0 "${AUD_ARGS[@]}" -shortest "$OUT/long_gop.mp4"

echo "== vfr.mp4: variable frame rate (every 5th frame dropped, original timestamps kept)"
"${FF[@]}" -f lavfi -i "$(VID 12 320x180 30)" -f lavfi -i "$(AUD 12 440)" -vf "select='gt(mod(n\,5)\,0)'" -vsync vfr \
  "${ENC_ARGS[@]}" -g 30 "${AUD_ARGS[@]}" -shortest "$OUT/vfr.mp4"

echo "== uhd.mp4: 3840x2160 video-only"
"${FF[@]}" -f lavfi -i "$(VID 3 3840x2160)" "${ENC_ARGS[@]}" -crf 35 -g 24 "$OUT/uhd.mp4"

if [ -n "${BIG:-}" ]; then
  echo "== big_lazy.mp4: > 64MB (lossless 1080p) → lazy box walk / head+tail paths"
  "${FF[@]}" -f lavfi -i "$(VID 22 1920x1080)" -f lavfi -i "$(AUD 22 440)" -c:v libx264 -preset ultrafast -qp 0 -pix_fmt yuv420p -g 24 \
    "${AUD_ARGS[@]}" -shortest "$OUT/big_lazy.mp4"
  SIZE=$(stat -c%s "$OUT/big_lazy.mp4")
  [ "$SIZE" -gt $((64*1024*1024)) ] || { echo "big_lazy.mp4 is only $SIZE bytes (need > 64MiB)" >&2; exit 1; }
fi

ls -la "$OUT"
echo "fixtures done"
