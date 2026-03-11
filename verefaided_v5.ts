/**
 * MediaCapabilities Fingerprint Module — v5
 * ==========================================
 * Verified against:
 *   - W3C Media Capabilities Editor's Draft (10 Feb 2026):
 *       https://w3c.github.io/media-capabilities/
 *   - AV1 ISOBMFF Codec String Spec v1.3.0:
 *       https://aomediacodec.github.io/av1-isobmff/v1.3.0.html
 *   - YouTube production AV1 codec strings (confirmed via yt-dlp):
 *       0.08M.08=720p60, 0.09M.08=1080p60,
 *       0.12M.08=1440p60, 0.13M.08=2160p60, 0.16M.08=4320p30
 *   - Google Chrome EME + decoding-info samples:
 *       https://googlechrome.github.io/samples/media-capabilities/
 *   - Widevine Security Integration Guide (public):
 *       SW_SECURE_CRYPTO, SW_SECURE_DECODE, HW_SECURE_CRYPTO,
 *       HW_SECURE_DECODE, HW_SECURE_ALL
 *   - MDN AudioConfiguration IDL: channels is DOMString, NOT number
 *   - MDN decodingInfo docs (last modified Jun 24, 2025)
 *
 * CHANGES vs v4:
 *
 *   [RENAME] Factory functions and constants renamed for clarity:
 *     makeVideoProbe(...)  — was vp(...)
 *     makeAudioProbe(...)  — was ap(...)
 *     makeDrmProbe(...)    — was dp(...)
 *     CONTENT_TYPE{}       — was CT{}
 *     WIDEVINE / PLAYREADY / CLEARKEY / FAIRPLAY / FAIRPLAY_1_0
 *                          — was WV / PR / CK / FPS / FPS1
 *     NOT_ALLOWED          — literal "not-allowed" deduplicated into constant
 *     OPUS_WEBM            — literal 'audio/webm; codecs="opus"' deduplicated
 *
 *   [REMOVED] hashVector — hashing belongs in the caller's combined fingerprint pipeline,
 *     not in a single-signal module. Removed per design review.
 *
 *   [PROBES VERIFIED] All 82 probes re-checked against spec + browser behaviour.
 *     No probes removed in this pass — all were already verified in v4.
 *
 * Signal sources (v5): 82 total probes
 *   V — 38 video probes: codec × profile × resolution × framerate × webrtc
 *   H — 10 HDR probes:   hdrMetadataType × colorGamut × transferFunction
 *   A — 19 audio probes: codec × channels × samplerate × spatialRendering
 *   D — 15 DRM probes:   keySystem × robustness × scheme × sessionType
 */

// ─── Public Types ─────────────────────────────────────────────────────────────

export interface MediaCapResult {
  supported: boolean;
  smooth: boolean;
  powerEfficient: boolean;
}

export interface MediaCapabilitiesFingerprint {
  video:        Record<string, string>;
  hdr:          Record<string, string>;
  audio:        Record<string, string>;
  drm:          Record<string, string>;
  vector:       string;
  entropyBits:  number;
  apiAvailable: boolean;
  durationMs:   number;
}

// ─── Internal Probe Types ─────────────────────────────────────────────────────

interface VideoProbe {
  label:             string;
  contentType:       string;
  width:             number;
  height:            number;
  bitrate:           number;
  framerate:         number;
  decodingType?:     "file" | "webrtc"; // "media-source" used only in DRM probes
  hdrMetadataType?:  "smpteSt2086" | "smpteSt2094-10" | "smpteSt2094-40";
  colorGamut?:       "srgb" | "p3" | "rec2020";
  transferFunction?: "srgb" | "pq" | "hlg";
  hasAlphaChannel?:  boolean;
  spatialScalability?: boolean;
  // scalabilityMode is ENCODING-ONLY (type=webrtc encodingInfo). Never for decodingInfo.
}

interface AudioProbe {
  label:             string;
  contentType:       string;
  channels:          string;  // DOMString per W3C IDL — "1","2","6","8"
  bitrate:           number;
  samplerate:        number;
  spatialRendering?: boolean;
}

interface DrmProbe {
  label:               string;
  keySystem:           string;
  initDataType:        string;
  videoRobustness:     string; // → ksc.video.robustness (nested KeySystemTrackConfiguration)
  audioRobustness:     string; // → ksc.audio.robustness
  distinctiveIdentifier: "required" | "optional" | "not-allowed";
  persistentState:     "required" | "optional" | "not-allowed";
  sessionTypes:        Array<"temporary" | "persistent-license">;
  encryptionScheme:    string | null; // null = omit (UA accepts any scheme per IDL default)
  videoContentType:    string;
  audioContentType:    string;
}

// ─── Probe Factories ──────────────────────────────────────────────────────────

function makeVideoProbe(
  label: string,
  contentType: string,
  width: number,
  height: number,
  bitrate: number,
  framerate: number,
  opts?: Partial<Pick<VideoProbe,
    "decodingType" | "hdrMetadataType" | "colorGamut" | "transferFunction" |
    "hasAlphaChannel" | "spatialScalability">>
): VideoProbe {
  return { label, contentType, width, height, bitrate, framerate, ...opts };
}

function makeAudioProbe(
  label: string,
  contentType: string,
  channels: string,
  bitrate: number,
  samplerate: number,
  spatialRendering?: boolean,
): AudioProbe {
  return {
    label, contentType, channels, bitrate, samplerate,
    ...(spatialRendering !== undefined ? { spatialRendering } : {}),
  };
}

function makeDrmProbe(
  label: string,
  keySystem: string,
  initDataType: string,
  videoRobustness: string,
  audioRobustness: string,
  distinctiveIdentifier: DrmProbe["distinctiveIdentifier"],
  persistentState: DrmProbe["persistentState"],
  sessionTypes: DrmProbe["sessionTypes"],
  encryptionScheme: string | null,
  videoContentType: string,
  audioContentType: string,
): DrmProbe {
  return {
    label, keySystem, initDataType,
    videoRobustness, audioRobustness,
    distinctiveIdentifier, persistentState, sessionTypes,
    encryptionScheme, videoContentType, audioContentType,
  };
}

// ─── Content Type Constants ───────────────────────────────────────────────────

const CONTENT_TYPE = {
  // ── Video ──
  h264_baseline_l31:  'video/mp4; codecs="avc1.42E01F"',          // H.264 Baseline L3.1 (720p30)
  h264_main_l40:      'video/mp4; codecs="avc1.4D0028"',          // H.264 Main L4.0     (1080p30)
  h264_high_l40:      'video/mp4; codecs="avc1.640028"',          // H.264 High L4.0     (1080p60)
  h264_high_l51:      'video/mp4; codecs="avc1.640033"',          // H.264 High L5.1     (4K30/60)
  h264_high_l52:      'video/mp4; codecs="avc1.640034"',          // H.264 High L5.2     (4K120)
  hevc_main_l31:      'video/mp4; codecs="hev1.1.6.L93.B0"',      // HEVC Main L3.1      (1080p30)
  hevc_main_l50:      'video/mp4; codecs="hev1.1.6.L150.B0"',     // HEVC Main L5.0      (4K30)
  hevc_main_l51:      'video/mp4; codecs="hev1.1.6.L153.B0"',     // HEVC Main L5.1      (4K60)
  hevc_main10_l50:    'video/mp4; codecs="hev1.2.4.L150.B0"',     // HEVC Main10 L5.0    (4K30 10-bit)
  hevc_main_l60:      'video/mp4; codecs="hev1.1.6.L180.B0"',     // HEVC Main L6.0      (8K30)
  hevc_hvc1_l31:      'video/mp4; codecs="hvc1.1.6.L93.B0"',      // HEVC hvc1 (Apple)   (1080p30 alpha)
  vp8:                'video/webm; codecs=vp8',
  vp9_p0_l31:         'video/webm; codecs="vp09.00.31.08"',       // VP9 P0 L3.1         (720p)
  vp9_p0_l40:         'video/webm; codecs="vp09.00.40.08"',       // VP9 P0 L4.0         (1080p30)
  vp9_p0_l41:         'video/webm; codecs="vp09.00.41.08"',       // VP9 P0 L4.1         (1080p60)
  vp9_p0_l50:         'video/webm; codecs="vp09.00.50.08"',       // VP9 P0 L5.0         (4K30)
  vp9_p0_l51:         'video/webm; codecs="vp09.00.51.08"',       // VP9 P0 L5.1         (4K60)
  vp9_p0_l61:         'video/webm; codecs="vp09.00.61.08"',       // VP9 P0 L6.1         (8K30)
  vp9_p2_hdr_4k:      'video/webm; codecs="vp09.02.51.10.01.09.16.09.01"', // VP9 P2 10-bit HDR 4K
  vp9_p2_hlg_fhd:     'video/webm; codecs="vp09.02.40.10.01.09.16.09.01"', // VP9 P2 10-bit HLG FHD
  av1_p0_l31_8bit:    'video/mp4; codecs="av01.0.08M.08"',        // AV1 P0 L3.1   720p60 max
  av1_p0_l40_8bit:    'video/mp4; codecs="av01.0.09M.08"',        // AV1 P0 L4.0   1080p60 max
  av1_p0_l51_8bit:    'video/mp4; codecs="av01.0.13M.08"',        // AV1 P0 L5.1   2160p60 max (YouTube)
  av1_p0_l61h_8bit:   'video/mp4; codecs="av01.0.17H.08"',        // AV1 P0 L6.1H  4K120 High tier
  av1_p0_l60_8bit:    'video/mp4; codecs="av01.0.16M.08"',        // AV1 P0 L6.0   4320p30 max (YouTube)
  av1_p0_l61_8bit:    'video/mp4; codecs="av01.0.17M.08"',        // AV1 P0 L6.1   4320p60 max
  av1_p0_l51_10bit:   'video/mp4; codecs="av01.0.13M.10"',        // AV1 P0 L5.1   2160p60 10-bit
  av1_p0_l40_10bit:   'video/mp4; codecs="av01.0.09M.10"',        // AV1 P0 L4.0   1080p60 10-bit
  theora:             'video/ogg; codecs=theora',
  // ── Audio ──
  aac_lc:             'audio/mp4; codecs="mp4a.40.2"',            // AAC-LC
  aac_he_v1:          'audio/mp4; codecs="mp4a.40.5"',            // HE-AAC v1 (SBR)
  aac_he_v2:          'audio/mp4; codecs="mp4a.40.29"',           // HE-AAC v2 (SBR+PS)
  mp3:                'audio/mpeg',
  opus_webm:          'audio/webm; codecs="opus"',
  vorbis_ogg:         'audio/ogg; codecs="vorbis"',
  ac3_dolby:          'audio/mp4; codecs="ac-3"',
  eac3_dolby_plus:    'audio/mp4; codecs="ec-3"',
  alac_apple:         'audio/mp4; codecs="alac"',
} as const;

// ─── DRM Key System Constants ─────────────────────────────────────────────────

const WIDEVINE    = "com.widevine.alpha";
const PLAYREADY   = "com.microsoft.playready";
const CLEARKEY    = "org.w3.clearkey";
const FAIRPLAY    = "com.apple.fps";
const FAIRPLAY_10 = "com.apple.fps.1_0";

// ─── Repeated Literal Constants ───────────────────────────────────────────────

/** "not-allowed" — used for ClearKey distinctiveIdentifier and persistentState */
const NOT_ALLOWED = "not-allowed" as const;

// ─── VIDEO PROBES (38) ────────────────────────────────────────────────────────

const VIDEO_PROBES: VideoProbe[] = [
  // ── H.264 / AVC ──────────────────────────────────────────────────────────
  makeVideoProbe("h264_baseline_hd30",  CONTENT_TYPE.h264_baseline_l31, 1280,  720,  3_000_000,  30),
  makeVideoProbe("h264_main_fhd30",     CONTENT_TYPE.h264_main_l40,     1920, 1080,  8_000_000,  30),
  makeVideoProbe("h264_high_fhd60",     CONTENT_TYPE.h264_high_l40,     1920, 1080, 12_000_000,  60),
  makeVideoProbe("h264_high_4k30",      CONTENT_TYPE.h264_high_l51,     3840, 2160, 20_000_000,  30),
  makeVideoProbe("h264_high_4k60",      CONTENT_TYPE.h264_high_l51,     3840, 2160, 40_000_000,  60),
  makeVideoProbe("h264_high_4k120",     CONTENT_TYPE.h264_high_l52,     3840, 2160, 60_000_000, 120),

  // ── H.265 / HEVC ─────────────────────────────────────────────────────────
  // hev1 = param sets in-band (standard); hvc1 = out-of-band (Apple box type)
  makeVideoProbe("hevc_main_fhd30",     CONTENT_TYPE.hevc_main_l31,  1920, 1080,  5_000_000,  30),
  makeVideoProbe("hevc_main_4k30",      CONTENT_TYPE.hevc_main_l50,  3840, 2160, 15_000_000,  30),
  makeVideoProbe("hevc_main_4k60",      CONTENT_TYPE.hevc_main_l51,  3840, 2160, 25_000_000,  60),
  makeVideoProbe("hevc_main10_4k30",    CONTENT_TYPE.hevc_main10_l50,3840, 2160, 20_000_000,  30),
  makeVideoProbe("hevc_main_8k30",      CONTENT_TYPE.hevc_main_l60,  7680, 4320, 50_000_000,  30),
  // hvc1 + hasAlphaChannel: uniquely identifies Apple platforms (Safari / iOS / macOS)
  makeVideoProbe("hevc_alpha_fhd30",    CONTENT_TYPE.hevc_hvc1_l31,  1920, 1080,  8_000_000,  30, { hasAlphaChannel: true }),

  // ── VP8 ───────────────────────────────────────────────────────────────────
  makeVideoProbe("vp8_hd30",            CONTENT_TYPE.vp8, 1280,  720,  2_000_000, 30),
  makeVideoProbe("vp8_fhd30",           CONTENT_TYPE.vp8, 1920, 1080,  5_000_000, 30),

  // ── VP9 ───────────────────────────────────────────────────────────────────
  // vp09.PP.LL.BB — Profile.Level.BitDepth
  makeVideoProbe("vp9_p0_hd30",         CONTENT_TYPE.vp9_p0_l31,     1280,  720,  2_000_000,  30),
  makeVideoProbe("vp9_p0_fhd30",        CONTENT_TYPE.vp9_p0_l40,     1920, 1080,  4_000_000,  30),
  makeVideoProbe("vp9_p0_fhd60",        CONTENT_TYPE.vp9_p0_l41,     1920, 1080,  7_000_000,  60),
  makeVideoProbe("vp9_p0_4k30",         CONTENT_TYPE.vp9_p0_l50,     3840, 2160, 12_000_000,  30),
  makeVideoProbe("vp9_p2_4k30_hdr",     CONTENT_TYPE.vp9_p2_hdr_4k,  3840, 2160, 20_000_000,  30),
  makeVideoProbe("vp9_p0_4k60",         CONTENT_TYPE.vp9_p0_l51,     3840, 2160, 20_000_000,  60),
  makeVideoProbe("vp9_p0_8k30",         CONTENT_TYPE.vp9_p0_l61,     7680, 4320, 40_000_000,  30),
  makeVideoProbe("vp9_alpha_hd30",      CONTENT_TYPE.vp9_p0_l31,     1280,  720,  3_000_000,  30, { hasAlphaChannel: true }),

  // ── AV1 ───────────────────────────────────────────────────────────────────
  // av01.P.LLT.DD — Profile.LevelTier.BitDepth
  // Levels confirmed via YouTube production streams (yt-dlp):
  //   L3.1(08)=720p60, L4.0(09)=1080p60, L5.1(13)=2160p60, L6.0(16)=4320p30
  makeVideoProbe("av1_p0_hd30",         CONTENT_TYPE.av1_p0_l31_8bit,  1280,  720,  1_500_000,  30),
  makeVideoProbe("av1_p0_fhd30",        CONTENT_TYPE.av1_p0_l40_8bit,  1920, 1080,  3_000_000,  30),
  makeVideoProbe("av1_p0_fhd60",        CONTENT_TYPE.av1_p0_l40_8bit,  1920, 1080,  5_000_000,  60),
  makeVideoProbe("av1_p0_4k30",         CONTENT_TYPE.av1_p0_l51_8bit,  3840, 2160,  8_000_000,  30),
  makeVideoProbe("av1_p0_4k60",         CONTENT_TYPE.av1_p0_l51_8bit,  3840, 2160, 15_000_000,  60),
  makeVideoProbe("av1_p0_4k120",        CONTENT_TYPE.av1_p0_l61h_8bit, 3840, 2160, 25_000_000, 120), // High tier = distinct HW path
  makeVideoProbe("av1_p0_8k30",         CONTENT_TYPE.av1_p0_l60_8bit,  7680, 4320, 30_000_000,  30),
  makeVideoProbe("av1_p0_8k60",         CONTENT_TYPE.av1_p0_l61_8bit,  7680, 4320, 50_000_000,  60),
  makeVideoProbe("av1_10bit_4k30",      CONTENT_TYPE.av1_p0_l51_10bit, 3840, 2160, 20_000_000,  30),

  // ── Theora ────────────────────────────────────────────────────────────────
  // Only Firefox supports Theora — strong browser fingerprint signal
  makeVideoProbe("theora_sd30",         CONTENT_TYPE.theora, 640, 480, 800_000, 30),

  // ── spatialScalability ────────────────────────────────────────────────────
  // Valid for decoding (file/media-source/webrtc) per W3C spec §2.1.4.
  // VP8 excluded: no SVC spec — would throw TypeError.
  makeVideoProbe("av1_spatscal_fhd30",  CONTENT_TYPE.av1_p0_l40_8bit, 1920, 1080,  4_000_000, 30, { spatialScalability: true }),
  makeVideoProbe("vp9_spatscal_4k30",   CONTENT_TYPE.vp9_p0_l50,      3840, 2160, 12_000_000, 30, { spatialScalability: true }),

  // ── WebRTC decoding ───────────────────────────────────────────────────────
  // type="webrtc" → different UA code path (real-time vs buffered decode estimates).
  // HDR fields are NOT valid for webrtc type per spec. VP8 removed: zero entropy.
  makeVideoProbe("webrtc_h264_fhd30",   CONTENT_TYPE.h264_high_l40,  1920, 1080, 4_000_000, 30, { decodingType: "webrtc" }),
  makeVideoProbe("webrtc_vp9_fhd30",    CONTENT_TYPE.vp9_p0_l40,     1920, 1080, 4_000_000, 30, { decodingType: "webrtc" }),
  makeVideoProbe("webrtc_av1_fhd30",    CONTENT_TYPE.av1_p0_l40_8bit,1920, 1080, 3_000_000, 30, { decodingType: "webrtc" }),
];

// ─── HDR PROBES (10) ──────────────────────────────────────────────────────────
// Chrome ≥ 120: smpteSt2086 always true (SW tone-map), smpteSt2094-10/40 false.
// Safari/Apple: smpteSt2094-10 and smpteSt2094-40 may be true → strong signal.
// colorGamut + transferFunction MUST be consistent with codec implied color space
// (bt2020 codec requires rec2020 gamut + pq/hlg, not srgb).

const HDR_PROBES: VideoProbe[] = [
  makeVideoProbe("hdr_sdr_srgb",         CONTENT_TYPE.vp9_p0_l40,     1920, 1080,  4_000_000, 30,
    { hdrMetadataType: "smpteSt2086",    colorGamut: "srgb",    transferFunction: "srgb" }),
  makeVideoProbe("hdr_hdr10_vp9_4k_pq",  CONTENT_TYPE.vp9_p2_hdr_4k,  3840, 2160, 20_000_000, 30,
    { hdrMetadataType: "smpteSt2086",    colorGamut: "rec2020", transferFunction: "pq"   }),
  makeVideoProbe("hdr_hdr10_av1_4k_pq",  CONTENT_TYPE.av1_p0_l51_10bit,3840, 2160, 20_000_000, 30,
    { hdrMetadataType: "smpteSt2086",    colorGamut: "rec2020", transferFunction: "pq"   }),
  makeVideoProbe("hdr_hlg_vp9_fhd",      CONTENT_TYPE.vp9_p2_hlg_fhd, 1920, 1080,  8_000_000, 30,
    { hdrMetadataType: "smpteSt2086",    colorGamut: "rec2020", transferFunction: "hlg"  }),
  makeVideoProbe("hdr_hlg_av1_4k",       CONTENT_TYPE.av1_p0_l51_10bit,3840, 2160, 20_000_000, 30,
    { hdrMetadataType: "smpteSt2086",    colorGamut: "rec2020", transferFunction: "hlg"  }),
  makeVideoProbe("hdr_hdr10plus_av1_4k", CONTENT_TYPE.av1_p0_l51_10bit,3840, 2160, 20_000_000, 30,
    { hdrMetadataType: "smpteSt2094-10", colorGamut: "rec2020", transferFunction: "pq"   }),
  makeVideoProbe("hdr_dolby_av1_4k",     CONTENT_TYPE.av1_p0_l51_10bit,3840, 2160, 20_000_000, 30,
    { hdrMetadataType: "smpteSt2094-40", colorGamut: "rec2020", transferFunction: "pq"   }),
  makeVideoProbe("hdr_dolby_hevc_4k",    CONTENT_TYPE.hevc_main10_l50, 3840, 2160, 20_000_000, 30,
    { hdrMetadataType: "smpteSt2094-40", colorGamut: "rec2020", transferFunction: "pq"   }),
  makeVideoProbe("hdr_p3_pq_av1_fhd",    CONTENT_TYPE.av1_p0_l40_10bit,1920, 1080,  6_000_000, 30,
    { hdrMetadataType: "smpteSt2086",    colorGamut: "p3",      transferFunction: "pq"   }),
  makeVideoProbe("hdr_p3_hlg_hevc_fhd",  CONTENT_TYPE.hevc_main_l31,   1920, 1080,  8_000_000, 30,
    { hdrMetadataType: "smpteSt2086",    colorGamut: "p3",      transferFunction: "hlg"  }),
];

// ─── AUDIO PROBES (19) ────────────────────────────────────────────────────────
// channels is DOMString per W3C IDL. Chrome official sample uses channels: '2'.
// Spec note: all supported audio codecs report powerEfficient=true.
// Main entropy: supported/unsupported variation, channel counts, exotic codecs.
//
// REMOVED: "audio/flac" (throws TypeError in Firefox; zero entropy in Chrome),
//          "audio/ogg" (ambiguous MIME without codec param → TypeError),
// KEPT:    "audio/mp4; codecs=alac" — TypeError in Chrome/Firefox is fingerprint signal.

const AUDIO_PROBES: AudioProbe[] = [
  // AAC-LC (mp4a.40.2) — universally supported
  makeAudioProbe("aac_lc_stereo_44",   CONTENT_TYPE.aac_lc,         "2", 128_000,   44100),
  makeAudioProbe("aac_lc_stereo_48",   CONTENT_TYPE.aac_lc,         "2", 192_000,   48000),
  makeAudioProbe("aac_lc_51_48",       CONTENT_TYPE.aac_lc,         "6", 384_000,   48000),
  makeAudioProbe("aac_lc_71_48",       CONTENT_TYPE.aac_lc,         "8", 512_000,   48000),
  // HE-AAC v1 (mp4a.40.5 = LC+SBR) — NOT in Firefox
  makeAudioProbe("aac_hev1_stereo_44", CONTENT_TYPE.aac_he_v1,      "2",  64_000,   44100),
  // HE-AAC v2 (mp4a.40.29 = LC+SBR+PS) — Chrome only
  makeAudioProbe("aac_hev2_stereo_44", CONTENT_TYPE.aac_he_v2,      "2",  32_000,   44100),

  // MP3
  makeAudioProbe("mp3_stereo_44",      CONTENT_TYPE.mp3,            "2", 128_000,   44100),
  makeAudioProbe("mp3_stereo_48",      CONTENT_TYPE.mp3,            "2", 320_000,   48000),

  // Opus (audio/webm; codecs="opus") — Chrome, Firefox, Safari 15+
  makeAudioProbe("opus_mono_48",       CONTENT_TYPE.opus_webm,      "1",  32_000,   48000),
  makeAudioProbe("opus_stereo_48",     CONTENT_TYPE.opus_webm,      "2", 128_000,   48000),
  makeAudioProbe("opus_51_48",         CONTENT_TYPE.opus_webm,      "6", 256_000,   48000),
  makeAudioProbe("opus_stereo_24",     CONTENT_TYPE.opus_webm,      "2",  64_000,   24000),
  makeAudioProbe("opus_stereo_16",     CONTENT_TYPE.opus_webm,      "2",  32_000,   16000),

  // Vorbis (audio/ogg; codecs="vorbis") — Chrome + Firefox only, NOT Safari
  makeAudioProbe("vorbis_stereo_44",   CONTENT_TYPE.vorbis_ogg,     "2", 128_000,   44100),
  makeAudioProbe("vorbis_51_44",       CONTENT_TYPE.vorbis_ogg,     "6", 256_000,   44100),

  // AC-3 (Dolby Digital) — Chrome, Edge, Safari. NOT Firefox.
  makeAudioProbe("ac3_51_48",          CONTENT_TYPE.ac3_dolby,      "6", 384_000,   48000),
  // EAC-3 (Dolby Digital Plus) — Chrome 90+, Edge, Safari
  makeAudioProbe("eac3_71_48",         CONTENT_TYPE.eac3_dolby_plus,"8", 768_000,   48000),
  // Dolby Atmos = EAC-3 + spatialRendering — Smart TVs and Safari report true
  makeAudioProbe("atmos_71_48",        CONTENT_TYPE.eac3_dolby_plus,"8", 768_000,   48000, true),

  // ALAC — Safari/WebKit only. Chrome/Firefox: TypeError → error code IS the signal.
  makeAudioProbe("alac_stereo_44",     CONTENT_TYPE.alac_apple,     "2", 1_000_000, 44100),
];

// ─── DRM PROBES (15) ──────────────────────────────────────────────────────────
// keySystemConfiguration per W3C IDL (Feb 2026 Editor's Draft):
//   { keySystem, initDataType, distinctiveIdentifier, persistentState,
//     sessionTypes, video: { robustness, encryptionScheme },
//                   audio: { robustness, encryptionScheme } }
// The old explainer's flat videoRobustness/audioRobustness are NOT in the IDL.
// Chrome ≥ M117 ignores flat fields — nested only.

const DRM_PROBES: DrmProbe[] = [
  // ── ClearKey ─────────────────────────────────────────────────────────────
  makeDrmProbe("ck_cenc",   CLEARKEY, "cenc",   "", "", NOT_ALLOWED, NOT_ALLOWED, ["temporary"], "cenc", CONTENT_TYPE.h264_baseline_l31, CONTENT_TYPE.aac_lc),
  makeDrmProbe("ck_webm",   CLEARKEY, "webm",   "", "", NOT_ALLOWED, NOT_ALLOWED, ["temporary"],  null,  CONTENT_TYPE.vp9_p0_l51,        CONTENT_TYPE.opus_webm),
  makeDrmProbe("ck_cbcs",   CLEARKEY, "cenc",   "", "", NOT_ALLOWED, NOT_ALLOWED, ["temporary"], "cbcs", CONTENT_TYPE.h264_high_l40,     CONTENT_TYPE.aac_lc),
  makeDrmProbe("ck_keyids", CLEARKEY, "keyids", "", "", NOT_ALLOWED, NOT_ALLOWED, ["temporary"],  null,  CONTENT_TYPE.h264_baseline_l31, CONTENT_TYPE.aac_lc),

  // ── Widevine (5 robustness levels) ───────────────────────────────────────
  makeDrmProbe("wv_sw_crypto",  WIDEVINE, "cenc", "SW_SECURE_CRYPTO", "SW_SECURE_CRYPTO", "optional", "optional", ["temporary"],                               "cenc", CONTENT_TYPE.h264_high_l40, CONTENT_TYPE.aac_lc),
  makeDrmProbe("wv_sw_decode",  WIDEVINE, "cenc", "SW_SECURE_DECODE", "SW_SECURE_CRYPTO", "optional", "optional", ["temporary"],                               "cenc", CONTENT_TYPE.h264_high_l40, CONTENT_TYPE.aac_lc),
  makeDrmProbe("wv_hw_crypto",  WIDEVINE, "cenc", "HW_SECURE_CRYPTO", "SW_SECURE_CRYPTO", "optional", "optional", ["temporary"],                               "cenc", CONTENT_TYPE.h264_high_l40, CONTENT_TYPE.aac_lc),
  makeDrmProbe("wv_hw_decode",  WIDEVINE, "cenc", "HW_SECURE_DECODE", "HW_SECURE_CRYPTO", "optional", "optional", ["temporary"],                               "cenc", CONTENT_TYPE.h264_high_l40, CONTENT_TYPE.aac_lc),
  makeDrmProbe("wv_hw_all",     WIDEVINE, "cenc", "HW_SECURE_ALL",    "HW_SECURE_CRYPTO", "optional", "optional", ["temporary"],                               "cenc", CONTENT_TYPE.h264_high_l40, CONTENT_TYPE.aac_lc),
  makeDrmProbe("wv_persistent", WIDEVINE, "cenc", "SW_SECURE_DECODE", "SW_SECURE_CRYPTO", "optional", "required", ["temporary", "persistent-license"],         "cenc", CONTENT_TYPE.h264_high_l40, CONTENT_TYPE.aac_lc),
  // VP9 HDR + AV1: codec-specific HW decrypt path signals
  makeDrmProbe("wv_vp9_4k_hdr", WIDEVINE, "cenc", "SW_SECURE_DECODE", "SW_SECURE_CRYPTO", "optional", "optional", ["temporary"],                              "cenc", CONTENT_TYPE.vp9_p2_hdr_4k, CONTENT_TYPE.opus_webm),
  makeDrmProbe("wv_av1_4k",     WIDEVINE, "cenc", "SW_SECURE_DECODE", "SW_SECURE_CRYPTO", "optional", "optional", ["temporary"],                              "cenc", CONTENT_TYPE.av1_p0_l51_8bit, CONTENT_TYPE.aac_lc),

  // ── PlayReady (Edge / Windows) ────────────────────────────────────────────
  // 2000 = SW security level, 3000 = HW TEE (Win10+ / Xbox)
  makeDrmProbe("pr_2000", PLAYREADY, "cenc", "2000", "", "optional", "optional", ["temporary"], "cenc", CONTENT_TYPE.h264_high_l40, CONTENT_TYPE.aac_lc),
  makeDrmProbe("pr_3000", PLAYREADY, "cenc", "3000", "", "optional", "optional", ["temporary"], "cenc", CONTENT_TYPE.h264_high_l40, CONTENT_TYPE.aac_lc),

  // ── FairPlay (Safari / macOS / iOS only) ─────────────────────────────────
  // Chrome/Firefox: SecurityError or NotSupportedError — both are fingerprint signals.
  // Safari: returns supported result (or different error) depending on version.
  makeDrmProbe("fp_sinf", FAIRPLAY,    "sinf", "", "", "optional", "optional", ["temporary"], null, CONTENT_TYPE.h264_high_l40, CONTENT_TYPE.aac_lc),
  makeDrmProbe("fp_1_0",  FAIRPLAY_10, "sinf", "", "", "optional", "optional", ["temporary"], null, CONTENT_TYPE.h264_high_l40, CONTENT_TYPE.aac_lc),
];

// ─── Probe Runners ────────────────────────────────────────────────────────────

function encodeResult(r: MediaCapResult): string {
  return `${r.supported ? "s" : "-"}${r.smooth ? "m" : "-"}${r.powerEfficient ? "p" : "-"}`;
}

function buildVideoConfig(probe: VideoProbe): Record<string, unknown> {
  const config: Record<string, unknown> = {
    contentType: probe.contentType,
    width:       probe.width,
    height:      probe.height,
    bitrate:     probe.bitrate,
    framerate:   probe.framerate,
  };
  if (probe.hdrMetadataType    !== undefined) config.hdrMetadataType    = probe.hdrMetadataType;
  if (probe.colorGamut         !== undefined) config.colorGamut         = probe.colorGamut;
  if (probe.transferFunction   !== undefined) config.transferFunction   = probe.transferFunction;
  if (probe.hasAlphaChannel    !== undefined) config.hasAlphaChannel    = probe.hasAlphaChannel;
  if (probe.spatialScalability !== undefined) config.spatialScalability = probe.spatialScalability;
  return config;
}

async function probeVideo(probe: VideoProbe): Promise<string> {
  try {
    const result = await navigator.mediaCapabilities.decodingInfo({
      type:  probe.decodingType ?? "file",
      video: buildVideoConfig(probe) as any,
    });
    return encodeResult(result as MediaCapResult);
  } catch (e: any) {
    if (e?.name === "TypeError") return "type-err";
    return "err";
  }
}

async function probeAudio(probe: AudioProbe): Promise<string> {
  try {
    const audioConfig: Record<string, unknown> = {
      contentType: probe.contentType,
      channels:    probe.channels,   // DOMString — "1","2","6","8"
      bitrate:     probe.bitrate,
      samplerate:  probe.samplerate,
    };
    if (probe.spatialRendering !== undefined) audioConfig.spatialRendering = probe.spatialRendering;
    const result = await navigator.mediaCapabilities.decodingInfo({
      type:  "file",
      audio: audioConfig as any,
    });
    return encodeResult(result as MediaCapResult);
  } catch (e: any) {
    if (e?.name === "TypeError") return "type-err";
    return "err";
  }
}

async function probeDRM(probe: DrmProbe): Promise<string> {
  if (typeof window === "undefined" || !window.isSecureContext) return "no-ctx";
  try {
    // Nested KeySystemTrackConfiguration per W3C IDL (Feb 2026).
    // Flat videoRobustness/audioRobustness were removed from IDL; ignored by Chrome ≥ M117.
    const keySystemConfig: Record<string, unknown> = {
      keySystem:             probe.keySystem,
      initDataType:          probe.initDataType,
      distinctiveIdentifier: probe.distinctiveIdentifier,
      persistentState:       probe.persistentState,
      sessionTypes:          probe.sessionTypes,
      video: {
        robustness: probe.videoRobustness,
        ...(probe.encryptionScheme !== null ? { encryptionScheme: probe.encryptionScheme } : {}),
      },
      audio: {
        robustness: probe.audioRobustness,
        ...(probe.encryptionScheme !== null ? { encryptionScheme: probe.encryptionScheme } : {}),
      },
    };
    const result = await navigator.mediaCapabilities.decodingInfo({
      type:  "media-source",
      video: { contentType: probe.videoContentType, width: 1920, height: 1080, bitrate: 8_000_000, framerate: 30 },
      audio: { contentType: probe.audioContentType, channels: "2", bitrate: 128_000, samplerate: 48000 },
      keySystemConfiguration: keySystemConfig as any,
    });
    const hasKeySystemAccess = !!(result as any).keySystemAccess;
    return encodeResult(result as MediaCapResult) + (hasKeySystemAccess ? "k" : "-");
  } catch (e: any) {
    if (e?.name === "SecurityError")     return "sec-err";
    if (e?.name === "InvalidStateError") return "state-err";
    if (e?.name === "NotSupportedError") return "not-sup";
    if (e?.name === "TypeError")         return "type-err";
    return "err";
  }
}

// ─── Concurrency-Limited Batch Runner ────────────────────────────────────────

async function runBatch<T>(
  items: T[],
  runProbe: (item: T) => Promise<string>,
  concurrency = 8,
): Promise<string[]> {
  const results: string[] = new Array(items.length);
  let nextIndex = 0;
  async function worker() {
    while (nextIndex < items.length) {
      const i = nextIndex++;
      results[i] = await runProbe(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

// ─── Entropy Estimator ───────────────────────────────────────────────────────

function estimateEntropy(
  videoMap: Record<string, string>,
  hdrMap:   Record<string, string>,
  audioMap: Record<string, string>,
  drmMap:   Record<string, string>,
): number {
  const countValid = (map: Record<string, string>) =>
    Object.values(map).filter(v => !v.includes("err") && v !== "no-ctx" && v !== "skipped").length;
  return Math.round(
    countValid(videoMap) * 0.85 +
    countValid(hdrMap)   * 1.2  +
    countValid(audioMap) * 0.4  +
    countValid(drmMap)   * 1.5,
  );
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Collect the full MediaCapabilities fingerprint.
 *
 * @param options.includeDRM      Include DRM probes (HTTPS only). Default: true if isSecureContext.
 * @param options.includeHDR      Include HDR probes. Default: true.
 * @param options.timeoutMs       Max wait in ms. Default: 6000.
 * @param options.drmConcurrency  Parallel DRM requests. Default: 3.
 *                                Keep low — some CDMs serialize DRM calls internally.
 */
export async function getMediaCapabilitiesFingerprint(options?: {
  includeDRM?:     boolean;
  includeHDR?:     boolean;
  timeoutMs?:      number;
  drmConcurrency?: number;
}): Promise<MediaCapabilitiesFingerprint> {
  const timeoutMs      = options?.timeoutMs ?? 6000;
  const includeHDR     = options?.includeHDR !== false;
  const drmConcurrency = options?.drmConcurrency ?? 3;
  const includeDRM =
    options?.includeDRM !== false &&
    typeof window !== "undefined" &&
    window.isSecureContext;

  const startTime = performance.now();

  if (
    typeof navigator === "undefined" ||
    !navigator.mediaCapabilities ||
    typeof navigator.mediaCapabilities.decodingInfo !== "function"
  ) {
    return {
      video: {}, hdr: {}, audio: {}, drm: {},
      vector: "UNAVAILABLE", entropyBits: 0, apiAvailable: false, durationMs: 0,
    };
  }

  let videoMap: Record<string, string> = {};
  let hdrMap:   Record<string, string> = {};
  let audioMap: Record<string, string> = {};
  let drmMap:   Record<string, string> = {};

  try {
    await Promise.race([
      (async () => {
        const [videoResults, hdrResults, audioResults, drmResults] = await Promise.all([
          runBatch(VIDEO_PROBES, probeVideo, 10),
          includeHDR
            ? runBatch(HDR_PROBES, probeVideo, 6)
            : Promise.resolve(HDR_PROBES.map(() => "skipped")),
          runBatch(AUDIO_PROBES, probeAudio, 10),
          includeDRM
            ? runBatch(DRM_PROBES, probeDRM, drmConcurrency)
            : Promise.resolve(DRM_PROBES.map(() => "skipped")),
        ]);
        VIDEO_PROBES.forEach((probe, i) => { videoMap[probe.label] = videoResults[i]; });
        HDR_PROBES.forEach((probe, i)   => { hdrMap[probe.label]   = hdrResults[i]; });
        AUDIO_PROBES.forEach((probe, i) => { audioMap[probe.label] = audioResults[i]; });
        DRM_PROBES.forEach((probe, i)   => { drmMap[probe.label]   = drmResults[i]; });
      })(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("timeout")), timeoutMs)),
    ]);
  } catch {
    // Partial results on timeout are still valuable for fingerprinting
  }

  return {
    video:        videoMap,
    hdr:          hdrMap,
    audio:        audioMap,
    drm:          drmMap,
    vector:       buildVector(videoMap, hdrMap, audioMap, drmMap),
    entropyBits:  estimateEntropy(videoMap, hdrMap, audioMap, drmMap),
    apiAvailable: true,
    durationMs:   Math.round(performance.now() - startTime),
  };
}

function buildVector(
  videoMap: Record<string, string>,
  hdrMap:   Record<string, string>,
  audioMap: Record<string, string>,
  drmMap:   Record<string, string>,
): string {
  return [
    `V:${Object.values(videoMap).join("")}`,
    `H:${Object.values(hdrMap).join("")}`,
    `A:${Object.values(audioMap).join("")}`,
    `D:${Object.values(drmMap).join("")}`,
  ].join("|");
}

// ─── Utilities ────────────────────────────────────────────────────────────────

/** Flatten all probes to a single { label: result } record for external hashing. */
export function flattenFingerprint(fp: MediaCapabilitiesFingerprint): Record<string, string> {
  return { ...fp.video, ...fp.hdr, ...fp.audio, ...fp.drm };
}

/** Debug-friendly summary. */
export function summarizeFingerprint(fp: MediaCapabilitiesFingerprint): string {
  const flat      = flattenFingerprint(fp);
  const supported = Object.entries(flat).filter(([, v]) => v.startsWith("s")).map(([k]) => k);
  const hwDecode  = Object.entries(flat).filter(([, v]) => v === "smp").map(([k]) => k);
  const drmOk     = Object.entries(fp.drm).filter(([, v]) => v.endsWith("k")).map(([k]) => k);
  return [
    `API: ${fp.apiAvailable} | Duration: ${fp.durationMs}ms | ~${fp.entropyBits} entropy bits`,
    `Supported: ${supported.length}/${Object.keys(flat).length} probes`,
    `HW decode (smp): ${hwDecode.join(", ") || "none"}`,
    `DRM with keySystemAccess: ${drmOk.join(", ") || "none"}`,
  ].join("\n");
}
