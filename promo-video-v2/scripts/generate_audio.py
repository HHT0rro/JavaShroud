#!/usr/bin/env python3
"""Generate deterministic, original audio for the JavaShroud v2 promo.

The generator intentionally uses synthesis only: no downloaded samples, loops,
or third-party audio assets.  The main cue is a 90.0 second, 126 BPM industrial
electronic bed written at 48 kHz stereo.  It also creates compact functional
effects for the mechanical-shutter / VMBC-open / terminal-proof moments.

Run from any directory:

    python scripts/generate_audio.py

Useful overrides for local checks:

    python scripts/generate_audio.py --output-dir assets/audio --seed 20260813

The byte stream is deterministic for the same Python + NumPy version, sample
rate, duration, and seed.  WAV metadata is deliberately omitted so output has
no wall-clock timestamps or non-repeatable tags.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import subprocess
import sys
import wave
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np


DEFAULT_SAMPLE_RATE = 48_000
DEFAULT_DURATION_SECONDS = 90.0
DEFAULT_BPM = 126.0
DEFAULT_SEED = 20_260_813
CHANNELS = 2
PCM_MAX = 32_767


@dataclass(frozen=True)
class AudioSpec:
    """Fixed technical format used by every generated WAV."""

    sample_rate: int
    duration_seconds: float
    bpm: float
    seed: int

    @property
    def frames(self) -> int:
        frames = round(self.sample_rate * self.duration_seconds)
        if not math.isclose(frames / self.sample_rate, self.duration_seconds, abs_tol=1e-12):
            raise ValueError("Duration is not representable as an integral frame count")
        return frames

    @property
    def beat_seconds(self) -> float:
        return 60.0 / self.bpm

    @property
    def beats(self) -> float:
        return self.duration_seconds / self.beat_seconds


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _sine(phase: np.ndarray) -> np.ndarray:
    return np.sin(2.0 * np.pi * phase, dtype=np.float64).astype(np.float32)


def _saw(phase: np.ndarray) -> np.ndarray:
    return (2.0 * (phase - np.floor(phase + 0.5))).astype(np.float32)


def _triangle(phase: np.ndarray) -> np.ndarray:
    return (2.0 * np.abs(2.0 * (phase - np.floor(phase + 0.5))) - 1.0).astype(np.float32)


def _exp_env(length: int, sample_rate: int, decay_seconds: float, floor: float = 0.0) -> np.ndarray:
    t = np.arange(length, dtype=np.float32) / sample_rate
    return (floor + (1.0 - floor) * np.exp(-t / max(decay_seconds, 1e-6))).astype(np.float32)


def _attack_release(length: int, sample_rate: int, attack: float, release: float) -> np.ndarray:
    """Raised-cosine attack and release envelope without discontinuous joins."""

    if length <= 0:
        return np.zeros(0, dtype=np.float32)
    envelope = np.ones(length, dtype=np.float32)
    attack_frames = min(length, max(1, int(round(attack * sample_rate))))
    release_frames = min(length, max(1, int(round(release * sample_rate))))
    attack_phase = np.linspace(0.0, math.pi, attack_frames, endpoint=True, dtype=np.float32)
    release_phase = np.linspace(0.0, math.pi, release_frames, endpoint=True, dtype=np.float32)
    envelope[:attack_frames] *= 0.5 - 0.5 * np.cos(attack_phase)
    envelope[-release_frames:] *= 0.5 + 0.5 * np.cos(release_phase)
    return envelope


def _one_pole_lowpass(signal: np.ndarray, coefficient: float) -> np.ndarray:
    """A deterministic first-order low-pass filter, implemented without SciPy."""

    output = np.empty_like(signal)
    previous = np.float32(0.0)
    coeff = np.float32(np.clip(coefficient, 0.0, 1.0))
    inv = np.float32(1.0) - coeff
    for index, current in enumerate(signal):
        previous = coeff * current + inv * previous
        output[index] = previous
    return output


def _high_pass_noise(noise: np.ndarray) -> np.ndarray:
    """Cheap, stable high-pass character for hats / mechanical noises."""

    smoothed = _one_pole_lowpass(noise, 0.12)
    high = noise - smoothed
    peak = float(np.max(np.abs(high))) or 1.0
    return (high / peak).astype(np.float32)


def _frequency(note: str) -> float:
    """Return equal-temperament frequency for a compact note spelling (e.g. F#2)."""

    names = {"C": 0, "C#": 1, "D": 2, "D#": 3, "E": 4, "F": 5, "F#": 6, "G": 7, "G#": 8, "A": 9, "A#": 10, "B": 11}
    if len(note) < 2:
        raise ValueError(f"Invalid note: {note!r}")
    accidental = "#" if len(note) >= 3 and note[1] == "#" else ""
    name = note[0] + accidental
    octave = int(note[len(name) :])
    midi = (octave + 1) * 12 + names[name]
    return 440.0 * (2.0 ** ((midi - 69) / 12.0))


def _pan_stereo(mono: np.ndarray, pan: float) -> np.ndarray:
    """Constant-power pan where -1 is left and +1 is right."""

    pan = float(np.clip(pan, -1.0, 1.0))
    angle = (pan + 1.0) * math.pi / 4.0
    return np.column_stack((mono * math.cos(angle), mono * math.sin(angle))).astype(np.float32)


class SynthBus:
    """A bounded stereo mix bus with frame-accurate placement."""

    def __init__(self, spec: AudioSpec) -> None:
        self.spec = spec
        self.samples = np.zeros((spec.frames, CHANNELS), dtype=np.float32)

    def add(self, time_seconds: float, mono: np.ndarray, gain: float = 1.0, pan: float = 0.0) -> None:
        start = int(round(time_seconds * self.spec.sample_rate))
        if start >= self.spec.frames or start + len(mono) <= 0:
            return
        source_start = max(0, -start)
        destination_start = max(0, start)
        length = min(len(mono) - source_start, self.spec.frames - destination_start)
        if length <= 0:
            return
        self.samples[destination_start : destination_start + length] += (
            _pan_stereo(mono[source_start : source_start + length], pan) * np.float32(gain)
        )

    def add_stereo(self, time_seconds: float, stereo: np.ndarray, gain: float = 1.0) -> None:
        start = int(round(time_seconds * self.spec.sample_rate))
        if start >= self.spec.frames or start + len(stereo) <= 0:
            return
        source_start = max(0, -start)
        destination_start = max(0, start)
        length = min(len(stereo) - source_start, self.spec.frames - destination_start)
        if length > 0:
            self.samples[destination_start : destination_start + length] += stereo[source_start : source_start + length] * np.float32(gain)


def _kick(sample_rate: int, tone: float = 1.0) -> np.ndarray:
    length = int(sample_rate * 0.245)
    t = np.arange(length, dtype=np.float32) / sample_rate
    frequency = (122.0 * tone) * np.exp(-t * 28.0) + 43.0
    phase = np.cumsum(frequency, dtype=np.float64) / sample_rate
    body = np.sin(2.0 * np.pi * phase).astype(np.float32) * _exp_env(length, sample_rate, 0.078)
    click_length = int(sample_rate * 0.012)
    click_t = np.arange(click_length, dtype=np.float32) / sample_rate
    click = np.sin(2.0 * np.pi * 2_300.0 * click_t).astype(np.float32) * np.exp(-click_t * 420.0)
    output = body * 0.95
    output[:click_length] += click.astype(np.float32) * 0.18
    return output.astype(np.float32)


def _snare(sample_rate: int, rng: np.random.Generator, brightness: float = 1.0) -> np.ndarray:
    length = int(sample_rate * 0.205)
    t = np.arange(length, dtype=np.float32) / sample_rate
    noise = _high_pass_noise(rng.standard_normal(length, dtype=np.float32))
    noise_env = np.exp(-t * (22.0 / brightness)).astype(np.float32)
    ring = np.sin(2.0 * np.pi * 188.0 * t).astype(np.float32) * np.exp(-t * 34.0)
    snap = np.sin(2.0 * np.pi * 1_050.0 * t).astype(np.float32) * np.exp(-t * 64.0)
    return (noise * noise_env * 0.55 + ring * 0.33 + snap * 0.10).astype(np.float32)


def _hat(sample_rate: int, rng: np.random.Generator, open_hat: bool = False) -> np.ndarray:
    seconds = 0.16 if open_hat else 0.055
    length = int(sample_rate * seconds)
    t = np.arange(length, dtype=np.float32) / sample_rate
    noise = _high_pass_noise(rng.standard_normal(length, dtype=np.float32))
    metallic = np.sin(2.0 * np.pi * (7_300.0 * t + 280.0 * t * t)).astype(np.float32)
    decay = 19.0 if open_hat else 78.0
    return ((noise * 0.72 + metallic * 0.20) * np.exp(-t * decay)).astype(np.float32)


def _bass(note_hz: float, sample_rate: int, duration: float, attack: float = 0.008) -> np.ndarray:
    length = max(1, int(round(sample_rate * duration)))
    t = np.arange(length, dtype=np.float32) / sample_rate
    phase = note_hz * t
    fundamental = _sine(phase)
    overtone = _triangle(phase * 2.0) * 0.22
    grit = _saw(phase * 0.5) * 0.09
    envelope = _attack_release(length, sample_rate, attack, min(0.095, duration * 0.35))
    return ((fundamental * 0.72 + overtone + grit) * envelope).astype(np.float32)


def _stab(notes: tuple[float, ...], sample_rate: int, duration: float, brightness: float) -> np.ndarray:
    length = max(1, int(round(sample_rate * duration)))
    t = np.arange(length, dtype=np.float32) / sample_rate
    sound = np.zeros(length, dtype=np.float32)
    for index, note_hz in enumerate(notes):
        phase = note_hz * t
        detune = _saw(phase * (1.002 + index * 0.0015)) * 0.34
        sine = _sine(phase) * 0.16
        sound += (detune + sine) / len(notes)
    envelope = _attack_release(length, sample_rate, 0.010, min(0.22, duration * 0.48))
    tremolo = 0.74 + 0.26 * _sine(7.0 * t)
    return (sound * envelope * tremolo * brightness).astype(np.float32)


def _industrial_pulse(sample_rate: int, frequency: float, duration: float, rng: np.random.Generator) -> np.ndarray:
    length = max(1, int(round(sample_rate * duration)))
    t = np.arange(length, dtype=np.float32) / sample_rate
    phase = frequency * t + 1.7 * np.square(t)
    carrier = _sine(phase + 0.16 * _sine(2.0 * t))
    noise = _high_pass_noise(rng.standard_normal(length, dtype=np.float32)) * 0.18
    envelope = _attack_release(length, sample_rate, 0.004, min(0.07, duration * 0.35))
    return ((carrier * 0.72 + noise) * envelope).astype(np.float32)


def _riser(sample_rate: int, seconds: float, rng: np.random.Generator) -> np.ndarray:
    length = max(1, int(round(sample_rate * seconds)))
    t = np.arange(length, dtype=np.float32) / sample_rate
    normalised = t / max(seconds, 1e-6)
    frequency = 120.0 + 1_100.0 * normalised * normalised
    phase = np.cumsum(frequency, dtype=np.float64) / sample_rate
    tone = _saw(phase) * 0.34 + _sine(phase * 0.499) * 0.18
    noise = _high_pass_noise(rng.standard_normal(length, dtype=np.float32)) * normalised * 0.17
    envelope = np.sin(np.clip(normalised, 0.0, 1.0) * math.pi / 2.0).astype(np.float32)
    return ((tone + noise) * envelope).astype(np.float32)


def _metal_tick(sample_rate: int, frequency: float, seconds: float) -> np.ndarray:
    length = max(1, int(round(sample_rate * seconds)))
    t = np.arange(length, dtype=np.float32) / sample_rate
    envelope = np.exp(-t * 45.0).astype(np.float32)
    overtones = (
        _sine(frequency * t) * 0.45
        + _sine(frequency * 2.73 * t) * 0.25
        + _sine(frequency * 4.11 * t) * 0.15
    )
    return (overtones * envelope).astype(np.float32)


def _section_gain(time_seconds: float, start: float, end: float, value: float, ramp: float = 0.24) -> float:
    """Finite raised-cosine section gain; avoids hard production boundaries."""

    if time_seconds < start or time_seconds >= end:
        return 0.0
    if ramp <= 0:
        return value
    if time_seconds < start + ramp:
        phase = (time_seconds - start) / ramp
        return value * (0.5 - 0.5 * math.cos(math.pi * phase))
    if time_seconds > end - ramp:
        phase = (end - time_seconds) / ramp
        return value * (0.5 - 0.5 * math.cos(math.pi * phase))
    return value


def _render_main_bed(spec: AudioSpec) -> np.ndarray:
    """Build the full original 126 BPM cue from deterministic oscillators/noise."""

    if not math.isclose(spec.beats, 189.0, abs_tol=1e-8):
        raise ValueError("The 90-second release cue must contain exactly 189 beats at 126 BPM")

    rng = np.random.default_rng(spec.seed)
    bus = SynthBus(spec)
    beat = spec.beat_seconds

    # Section labels mirror the locked video timing, so editors can align the
    # sound-design landmarks without retiming the bed.
    arrangement = (
        (0.0, 5.0, "cross-platform hook"),
        (5.0, 10.0, "statement"),
        (10.0, 30.0, "build witness"),
        (30.0, 45.0, "cfr evidence"),
        (45.0, 60.0, "vmbc climax"),
        (60.0, 68.0, "flow and strings"),
        (68.0, 78.0, "artifact structure"),
        (78.0, 86.0, "result match"),
        (86.0, 90.0, "cta"),
    )
    _ = arrangement  # Documents the fixed musical map and keeps it inspectable.

    # Deep sub pulse: it arrives immediately, then remains quietly underneath
    # every engineering segment to make the product feel like a machine.
    for beat_index in range(math.ceil(spec.beats)):
        time_seconds = beat_index * beat
        if time_seconds >= spec.duration_seconds:
            break
        intro_gain = _section_gain(time_seconds, 0.0, 10.0, 0.30)
        body_gain = _section_gain(time_seconds, 10.0, 86.0, 0.76)
        cta_gain = _section_gain(time_seconds, 86.0, 90.0, 0.46, ramp=0.10)
        kick_gain = intro_gain + body_gain + cta_gain
        if kick_gain:
            accent = 1.13 if beat_index % 4 == 0 else 0.94
            bus.add(time_seconds, _kick(spec.sample_rate, 1.0 + (beat_index % 16 == 0) * 0.035), kick_gain * accent, pan=-0.025)

        # Off-beat engine ticks establish technical motion before the full beat
        # opens.  The more dense sections retain them at a lower level.
        tick_gain = (
            _section_gain(time_seconds, 0.0, 10.0, 0.44)
            + _section_gain(time_seconds, 10.0, 45.0, 0.19)
            + _section_gain(time_seconds, 45.0, 60.0, 0.28)
            + _section_gain(time_seconds, 68.0, 86.0, 0.23)
        )
        if tick_gain:
            bus.add(time_seconds + beat * 0.50, _metal_tick(spec.sample_rate, 1_980.0 + (beat_index % 5) * 145.0, 0.11), tick_gain, pan=0.35)

    # 16th-note hats emerge during build evidence, tighten at the VMBC climax,
    # and return for the final proof.  A seeded pattern gives repeatable motion.
    sixteenth = beat / 4.0
    for step in range(math.ceil(spec.duration_seconds / sixteenth)):
        time_seconds = step * sixteenth
        if time_seconds >= spec.duration_seconds:
            break
        position = step % 16
        density = (
            _section_gain(time_seconds, 10.0, 30.0, 0.19)
            + _section_gain(time_seconds, 30.0, 45.0, 0.26)
            + _section_gain(time_seconds, 45.0, 60.0, 0.42)
            + _section_gain(time_seconds, 60.0, 68.0, 0.16)
            + _section_gain(time_seconds, 68.0, 86.0, 0.34)
        )
        if density <= 0:
            continue
        pattern_gain = 1.0 if position in (0, 2, 4, 6, 8, 10, 12, 14) else 0.52
        if position in (3, 7, 11, 15):
            pattern_gain *= 0.64
        if rng.random() < 0.92:
            pan = -0.26 if position % 4 in (0, 3) else 0.28
            bus.add(time_seconds, _hat(spec.sample_rate, rng, open_hat=position == 14 and density > 0.30), density * pattern_gain, pan=pan)

    # A short metallic backbeat starts at the build witness and deliberately
    # disappears during the 60-68s evidence reset.
    for beat_index in range(math.ceil(spec.beats)):
        time_seconds = beat_index * beat
        if beat_index % 4 not in (1, 3):
            continue
        gain = (
            _section_gain(time_seconds, 10.0, 45.0, 0.38)
            + _section_gain(time_seconds, 45.0, 60.0, 0.48)
            + _section_gain(time_seconds, 68.0, 86.0, 0.44)
        )
        if gain:
            bus.add(time_seconds, _snare(spec.sample_rate, rng, brightness=1.12), gain, pan=0.06)

    # F# minor-derived bass motion (F#, E, D, C#) creates a purposeful launch
    # feel without borrowing any melodic material from external recordings.
    bass_pattern = ("F#1", "F#1", "E1", "C#1", "D1", "E1", "F#1", "C#2")
    for beat_index in range(math.ceil(spec.beats)):
        time_seconds = beat_index * beat
        if time_seconds >= spec.duration_seconds:
            break
        gain = (
            _section_gain(time_seconds, 10.0, 30.0, 0.35)
            + _section_gain(time_seconds, 30.0, 45.0, 0.47)
            + _section_gain(time_seconds, 45.0, 60.0, 0.64)
            + _section_gain(time_seconds, 60.0, 68.0, 0.18)
            + _section_gain(time_seconds, 68.0, 86.0, 0.56)
            + _section_gain(time_seconds, 86.0, 90.0, 0.35, ramp=0.10)
        )
        if gain:
            note = _frequency(bass_pattern[beat_index % len(bass_pattern)])
            duration = beat * (0.78 if beat_index % 2 == 0 else 0.59)
            bus.add(time_seconds, _bass(note, spec.sample_rate, duration), gain, pan=-0.09)

    # Chord stabs follow the visual "passes / rules / TOML" pace.  These are
    # compact and sparse, leaving the captions intelligible when sound is low.
    chord_cycle = (
        (_frequency("F#3"), _frequency("A3"), _frequency("C#4")),
        (_frequency("E3"), _frequency("G#3"), _frequency("B3")),
        (_frequency("D3"), _frequency("F#3"), _frequency("A3")),
        (_frequency("C#3"), _frequency("E3"), _frequency("G#3")),
    )
    for bar_index, time_seconds in enumerate(np.arange(10.0, 86.0, beat * 4.0)):
        gain = (
            _section_gain(float(time_seconds), 10.0, 30.0, 0.23)
            + _section_gain(float(time_seconds), 30.0, 45.0, 0.32)
            + _section_gain(float(time_seconds), 45.0, 60.0, 0.46)
            + _section_gain(float(time_seconds), 68.0, 86.0, 0.37)
        )
        if gain:
            bus.add(float(time_seconds), _stab(chord_cycle[bar_index % len(chord_cycle)], spec.sample_rate, beat * 1.5, 1.0), gain, pan=0.18)
            if gain > 0.35:
                bus.add(float(time_seconds + beat * 1.5), _industrial_pulse(spec.sample_rate, 584.0 + (bar_index % 3) * 52.0, beat * 0.42, rng), gain * 0.44, pan=-0.38)

    # Visual transition landmarks: 10s opening into the workstation, 45s VMBC
    # compression/open, 68s artifact tree, and 78s matching cross-platform run.
    for time_seconds, seconds, gain, pan in (
        (9.10, 0.88, 0.34, -0.28),
        (44.12, 0.88, 0.58, 0.04),
        (67.10, 0.74, 0.40, 0.22),
        (77.05, 0.78, 0.54, -0.12),
    ):
        bus.add(time_seconds, _riser(spec.sample_rate, seconds, rng), gain, pan=pan)

    # VMBC climax: a deliberate compressed strike / expansion cluster reserved
    # for the single high-energy transformation instead of repeated gimmicks.
    vmbc_time = 45.0
    bus.add(vmbc_time - 0.30, _riser(spec.sample_rate, 0.30, rng), 0.72, pan=-0.08)
    bus.add(vmbc_time, _industrial_pulse(spec.sample_rate, 74.0, 0.48, rng), 0.92, pan=-0.04)
    bus.add(vmbc_time + 0.045, _metal_tick(spec.sample_rate, 3_120.0, 0.19), 0.73, pan=0.28)
    bus.add(vmbc_time + 0.09, _kick(spec.sample_rate, 0.84), 0.66, pan=0.0)

    # CTA drops density and resolves with four restrained hardware pulses.
    for offset, note in enumerate(("F#3", "C#4", "E4", "F#4")):
        time_seconds = 86.05 + offset * 0.76
        if time_seconds < 89.5:
            bus.add(time_seconds, _industrial_pulse(spec.sample_rate, _frequency(note), 0.30, rng), 0.23, pan=(-0.22 + 0.15 * offset))

    # A tiny ambient film grain makes the fully synthetic bed feel less brittle.
    noise = rng.standard_normal(spec.frames, dtype=np.float32)
    ambient = _one_pole_lowpass(noise, 0.015) * 0.0065
    bus.add(0.0, ambient, 1.0, pan=0.0)

    # Gentle mastering: soft saturation and a deterministic -1.0 dBFS ceiling.
    mixed = np.tanh(bus.samples * np.float32(1.18)).astype(np.float32)
    fade_in = min(spec.frames, int(round(spec.sample_rate * 0.025)))
    mixed[:fade_in] *= np.linspace(0.0, 1.0, fade_in, endpoint=True, dtype=np.float32)[:, None]
    fade_out = min(spec.frames, int(round(spec.sample_rate * 0.650)))
    mixed[-fade_out:] *= np.linspace(1.0, 0.0, fade_out, endpoint=True, dtype=np.float32)[:, None]
    peak = float(np.max(np.abs(mixed))) or 1.0
    ceiling = 10.0 ** (-1.0 / 20.0)
    return (mixed * np.float32(ceiling / peak)).astype(np.float32)


def _sfx_shutter(sample_rate: int, rng: np.random.Generator) -> np.ndarray:
    seconds = 0.56
    length = int(sample_rate * seconds)
    t = np.arange(length, dtype=np.float32) / sample_rate
    hard_noise = _high_pass_noise(rng.standard_normal(length, dtype=np.float32))
    click_a = np.exp(-t * 145.0) * hard_noise * 0.80
    click_b = np.zeros(length, dtype=np.float32)
    second_start = int(sample_rate * 0.165)
    second_t = t[: length - second_start]
    click_b[second_start:] = np.exp(-second_t * 108.0) * hard_noise[: length - second_start] * 0.66
    whirr = _sine(460.0 * t + 760.0 * t * t) * np.exp(-t * 10.0) * 0.25
    return (click_a + click_b + whirr).astype(np.float32)


def _sfx_grid_dissolve(sample_rate: int, rng: np.random.Generator) -> np.ndarray:
    seconds = 0.82
    length = int(sample_rate * seconds)
    t = np.arange(length, dtype=np.float32) / sample_rate
    normalised = t / seconds
    noise = _high_pass_noise(rng.standard_normal(length, dtype=np.float32))
    down = _sine(2_350.0 * t - 1_780.0 * t * t) * (1.0 - normalised) * 0.36
    digital = np.sign(_sine(1_200.0 * t + 5_000.0 * t * t)) * np.exp(-t * 9.0) * 0.16
    envelope = _attack_release(length, sample_rate, 0.006, 0.30)
    return ((noise * 0.30 + down + digital) * envelope).astype(np.float32)


def _sfx_vmbc_open(sample_rate: int, rng: np.random.Generator) -> np.ndarray:
    seconds = 1.08
    length = int(sample_rate * seconds)
    t = np.arange(length, dtype=np.float32) / sample_rate
    normalised = t / seconds
    rise_frequency = 84.0 + 2_280.0 * normalised * normalised
    phase = np.cumsum(rise_frequency, dtype=np.float64) / sample_rate
    rise = _saw(phase) * np.sin(math.pi * np.minimum(normalised, 1.0)).astype(np.float32) * 0.32
    body = _sine(76.0 * t) * np.exp(-t * 8.5) * 0.56
    noise = _high_pass_noise(rng.standard_normal(length, dtype=np.float32)) * np.exp(-np.maximum(t - 0.30, 0.0) * 5.2) * 0.16
    impact_index = int(sample_rate * 0.72)
    impact_t = t[: length - impact_index]
    impact = np.zeros(length, dtype=np.float32)
    impact[impact_index:] = (
        _sine(58.0 * impact_t) * np.exp(-impact_t * 15.0) * 0.80
        + _high_pass_noise(rng.standard_normal(length - impact_index, dtype=np.float32)) * np.exp(-impact_t * 34.0) * 0.24
    )
    return (rise + body + noise + impact).astype(np.float32)


def _sfx_terminal_tick(sample_rate: int) -> np.ndarray:
    seconds = 0.18
    length = int(sample_rate * seconds)
    t = np.arange(length, dtype=np.float32) / sample_rate
    tone = (
        _sine(2_120.0 * t) * 0.55
        + _sine(3_380.0 * t) * 0.25
        + _sine(4_710.0 * t) * 0.10
    )
    return (tone * np.exp(-t * 46.0)).astype(np.float32)


def _sfx_result_match(sample_rate: int, rng: np.random.Generator) -> np.ndarray:
    seconds = 0.68
    length = int(sample_rate * seconds)
    t = np.arange(length, dtype=np.float32) / sample_rate
    chime_a = _sine(_frequency("F#5") * t) * np.exp(-t * 6.5) * 0.42
    chime_b = np.zeros(length, dtype=np.float32)
    start = int(sample_rate * 0.118)
    late_t = t[: length - start]
    chime_b[start:] = _sine(_frequency("C#6") * late_t) * np.exp(-late_t * 8.0) * 0.34
    air = _high_pass_noise(rng.standard_normal(length, dtype=np.float32)) * np.exp(-t * 15.0) * 0.075
    return (chime_a + chime_b + air).astype(np.float32)


def _write_wav(path: Path, samples: np.ndarray, sample_rate: int) -> dict[str, float | int | str]:
    """Write deterministic stereo signed-16-bit PCM and return inspectable facts."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if samples.ndim == 1:
        samples = np.column_stack((samples, samples))
    if samples.shape[1] != CHANNELS:
        raise ValueError(f"Expected stereo samples, got shape {samples.shape}")
    clipped = np.clip(samples, -1.0, 1.0)
    # Round once at the PCM boundary.  wave writes bare RIFF PCM, without
    # timestamped metadata chunks, so exact output remains reproducible.
    pcm = np.rint(clipped * PCM_MAX).astype("<i2", copy=False)
    with wave.open(str(path), "wb") as handle:
        handle.setnchannels(CHANNELS)
        handle.setsampwidth(2)
        handle.setframerate(sample_rate)
        handle.setcomptype("NONE", "not compressed")
        handle.writeframes(pcm.tobytes(order="C"))
    sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "path": str(path),
        "sample_rate": sample_rate,
        "channels": CHANNELS,
        "sample_width_bits": 16,
        "frames": int(len(pcm)),
        "duration_seconds": len(pcm) / sample_rate,
        "sha256": sha256,
    }


def _master_sfx(mono: np.ndarray) -> np.ndarray:
    stereo = _pan_stereo(mono, 0.0)
    stereo = np.tanh(stereo * np.float32(1.12)).astype(np.float32)
    peak = float(np.max(np.abs(stereo))) or 1.0
    return (stereo * np.float32((10.0 ** (-1.5 / 20.0)) / peak)).astype(np.float32)


def _ffprobe_duration(path: Path) -> float | None:
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        return None
    completed = subprocess.run(
        [
            ffprobe,
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "json",
            str(path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    return float(payload["format"]["duration"])


def _verify_main_track(path: Path, expected: AudioSpec) -> None:
    with wave.open(str(path), "rb") as handle:
        actual_frames = handle.getnframes()
        actual_rate = handle.getframerate()
        actual_channels = handle.getnchannels()
        actual_width = handle.getsampwidth()
    if actual_rate != expected.sample_rate or actual_channels != CHANNELS or actual_width != 2:
        raise RuntimeError("Main WAV format did not match the fixed delivery spec")
    if actual_frames != expected.frames:
        raise RuntimeError(f"Main WAV frame count mismatch: {actual_frames} != {expected.frames}")
    duration = actual_frames / actual_rate
    if not math.isclose(duration, expected.duration_seconds, abs_tol=1e-12):
        raise RuntimeError(f"Main WAV duration mismatch: {duration} != {expected.duration_seconds}")
    ffprobe_duration = _ffprobe_duration(path)
    if ffprobe_duration is not None and not math.isclose(ffprobe_duration, expected.duration_seconds, abs_tol=1e-6):
        raise RuntimeError(f"ffprobe duration mismatch: {ffprobe_duration} != {expected.duration_seconds}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_project_root() / "assets" / "audio",
        help="Directory that will receive the generated WAV files.",
    )
    parser.add_argument("--sample-rate", type=int, default=DEFAULT_SAMPLE_RATE, help="PCM sample rate in Hz (default: 48000).")
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION_SECONDS, help="Main bed duration in seconds (default: 90.0).")
    parser.add_argument("--bpm", type=float, default=DEFAULT_BPM, help="Tempo of the main bed (default: 126.0).")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Seed for deterministic noise components.")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    spec = AudioSpec(
        sample_rate=args.sample_rate,
        duration_seconds=args.duration,
        bpm=args.bpm,
        seed=args.seed,
    )
    if spec.sample_rate <= 0 or spec.duration_seconds <= 0 or spec.bpm <= 0:
        raise ValueError("sample rate, duration, and BPM must all be positive")
    if not math.isclose(spec.duration_seconds, DEFAULT_DURATION_SECONDS, abs_tol=1e-12):
        raise ValueError("The release asset must remain exactly 90.0 seconds")
    if not math.isclose(spec.bpm, DEFAULT_BPM, abs_tol=1e-12):
        raise ValueError("The release asset must remain at 126 BPM")
    if spec.sample_rate != DEFAULT_SAMPLE_RATE:
        raise ValueError("The release asset must remain 48 kHz")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    ffmpeg = shutil.which("ffmpeg")
    ffprobe = shutil.which("ffprobe")
    print(f"ffmpeg={'available' if ffmpeg else 'not found'}" + (f" ({ffmpeg})" if ffmpeg else ""))
    print(f"ffprobe={'available' if ffprobe else 'not found'}" + (f" ({ffprobe})" if ffprobe else ""))
    print(f"main_bed: {spec.duration_seconds:.1f}s, {spec.sample_rate}Hz, stereo, 16-bit PCM, {spec.bpm:.0f} BPM, {spec.beats:.0f} beats")

    reports: list[dict[str, float | int | str]] = []
    main_path = args.output_dir / "javashroud-industrial-126bpm.wav"
    reports.append(_write_wav(main_path, _render_main_bed(spec), spec.sample_rate))
    _verify_main_track(main_path, spec)

    # Separate seeded streams make each effect reproducible and prevent a tiny
    # arrangement edit from mutating any unrelated SFX asset.
    effects: tuple[tuple[str, Callable[..., np.ndarray], int], ...] = (
        ("sfx-mechanical-shutter.wav", _sfx_shutter, 1),
        ("sfx-grid-dissolve.wav", _sfx_grid_dissolve, 2),
        ("sfx-vmbc-open.wav", _sfx_vmbc_open, 3),
        ("sfx-terminal-tick.wav", _sfx_terminal_tick, 4),
        ("sfx-result-match.wav", _sfx_result_match, 5),
    )
    for filename, renderer, stream in effects:
        effect_rng = np.random.default_rng(spec.seed + stream * 10_007)
        if renderer is _sfx_terminal_tick:
            mono = renderer(spec.sample_rate)
        else:
            mono = renderer(spec.sample_rate, effect_rng)
        reports.append(_write_wav(args.output_dir / filename, _master_sfx(mono), spec.sample_rate))

    print("Generated original synthesis assets:")
    for report in reports:
        duration = float(report["duration_seconds"])
        print(
            "  {name}: {duration:.6f}s | {frames} frames | sha256={digest}".format(
                name=Path(str(report["path"])).name,
                duration=duration,
                frames=report["frames"],
                digest=str(report["sha256"]),
            )
        )
    if ffprobe:
        print(f"ffprobe_main_duration={_ffprobe_duration(main_path):.6f}s")
    print("Verification: PASS (frame-exact 90.000000s main bed)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"generate_audio.py: {error}", file=sys.stderr)
        raise SystemExit(1)
