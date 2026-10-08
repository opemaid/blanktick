#!/usr/bin/env python3
# Fun, upbeat 16s ad music bed for the Blanktick "superhero vs minions" ad.
# Pure numpy synthesis, offline (no samples, no network). Writes a 44.1k mono WAV.
# Structure follows the film beats: cheeky intro -> swarm groove -> riser ->
# POW impact -> triumphant hero -> resolve. BPM 128, key G major.
import sys, wave, struct, math
import numpy as np

SR = 44100
DUR = 16.0
BPM = 128.0
SPB = 60.0 / BPM          # seconds per beat (0.46875)
N = int(SR * DUR)
buf = np.zeros(N, dtype=np.float64)

def idx(t): return int(t * SR)

def osc(freq, dur, kind='sine', detune=0.0):
    n = int(dur * SR)
    t = np.arange(n) / SR
    f = freq * (1.0 + detune)
    ph = 2 * np.pi * f * t
    if kind == 'sine':   w = np.sin(ph)
    elif kind == 'tri':  w = 2 / np.pi * np.arcsin(np.sin(ph))
    elif kind == 'square': w = np.sign(np.sin(ph)) * 0.8
    elif kind == 'saw':  w = 2 * (t * f - np.floor(0.5 + t * f))
    else: w = np.sin(ph)
    return w

def env_adsr(n, a=0.005, d=0.05, s=0.7, r=0.08):
    a_n, d_n, r_n = int(a*SR), int(d*SR), int(r*SR)
    e = np.ones(n)
    if a_n > 0: e[:a_n] = np.linspace(0, 1, a_n)
    if d_n > 0 and a_n+d_n < n: e[a_n:a_n+d_n] = np.linspace(1, s, d_n)
    if a_n+d_n < n: e[a_n+d_n:] = s
    if r_n > 0 and r_n < n: e[-r_n:] *= np.linspace(1, 0, r_n)
    return e

def add(t, sig, gain=1.0):
    i = idx(t); j = min(N, i + len(sig))
    if i >= N: return
    buf[i:j] += sig[:j-i] * gain

def note(t, freq, dur, kind='tri', gain=0.3, a=0.005, d=0.05, s=0.7, r=0.08, detune=0.0):
    w = osc(freq, dur, kind, detune)
    add(t, w * env_adsr(len(w), a, d, s, r), gain)

# --- percussion ---
def kick(t, gain=0.9):
    n = int(0.18*SR); tt = np.arange(n)/SR
    f = 120 * np.exp(-tt*28) + 45
    w = np.sin(2*np.pi*np.cumsum(f)/SR)
    w *= np.exp(-tt*16)
    add(t, w, gain)

def hat(t, gain=0.18, dur=0.04):
    n = int(dur*SR)
    w = (np.random.default_rng(int(t*1000)).random(n)*2-1)
    w *= np.exp(-np.arange(n)/SR*90)
    add(t, w, gain)

def clap(t, gain=0.5):
    n = int(0.12*SR); rng = np.random.default_rng(7)
    w = (rng.random(n)*2-1) * np.exp(-np.arange(n)/SR*34)
    add(t, w, gain)

def riser(t, dur=0.9, gain=0.33):
    n = int(dur*SR); tt = np.arange(n)/SR
    f = 200 * np.power(10, tt/dur*1.1)         # sweep up
    w = np.sin(2*np.pi*np.cumsum(f)/SR)
    rng = np.random.default_rng(3)
    w = 0.6*w + 0.4*(rng.random(n)*2-1)
    w *= np.linspace(0.2, 1.0, n)              # swell in
    add(t, w, gain)

def crash(t, gain=0.5, dur=1.2):
    n = int(dur*SR); rng = np.random.default_rng(99)
    w = (rng.random(n)*2-1) * np.exp(-np.arange(n)/SR*4.5)
    add(t, w, gain)

def boom(t, gain=1.0):
    n = int(0.5*SR); tt = np.arange(n)/SR
    f = 90*np.exp(-tt*9) + 38
    w = np.sin(2*np.pi*np.cumsum(f)/SR) * np.exp(-tt*6)
    add(t, w, gain)

# --- note helpers (G major) ---
A4 = 440.0
def hz(semis_from_a4): return A4 * (2 ** (semis_from_a4/12.0))
# scale degrees around G: G=-2, A=0, B=2, C=3, D=5, E=7, F#=9, G=10 (semitones from A4-ish octave)
NOTE = {'G3':hz(-14),'A3':hz(-12),'B3':hz(-10),'C4':hz(-9),'D4':hz(-7),'E4':hz(-5),'Fs4':hz(-3),
        'G4':hz(-2),'A4':hz(0),'B4':hz(2),'C5':hz(3),'D5':hz(5),'E5':hz(7),'Fs5':hz(9),'G5':hz(10)}

# chord roots per bar (I V vi IV, lifted) — 8 bars of 4 beats; bar starts:
chords = ['G3','D4','E4','C4','G3','D4','E4','C4']   # G  D  Em  C ...
chord_tones = {'G3':['G3','B3','D4'],'D4':['D4','Fs4','A4'],'E4':['E4','G4','B4'],'C4':['C4','E4','G4']}

t0 = 0.0
BAR = 4*SPB

# groove starts at ~1.0s (bar 0 intro is light)
for bar in range(8):
    bt = 1.0 + bar*BAR
    if bt >= DUR: break
    root = chords[bar]
    # bass: bouncy 8ths (root, octave) — skip heavy bass in the very intro bar
    for k in range(8):
        tb = bt + k*SPB/2
        if tb >= DUR: break
        f = NOTE[root] * (1.0 if k % 2 == 0 else 2.0)
        note(tb, f, SPB*0.45, kind='tri', gain=0.22 if bar>0 else 0.12, a=0.004, d=0.06, s=0.5, r=0.05)
    # drums
    for b in range(4):
        tb = bt + b*SPB
        if tb >= DUR: break
        if bar >= 1: kick(tb, gain=0.95)
        if b in (1,3) and bar >= 1: clap(tb, gain=0.42)
        hat(tb + SPB/2, gain=0.16)
        hat(tb + SPB*0.25, gain=0.08)
    # lead arpeggio (brighter from bar 3 = hero section)
    tones = chord_tones[root]
    arp = [tones[0], tones[1], tones[2], tones[1]]
    lead_gain = 0.0 if bar == 0 else (0.16 if bar < 3 else 0.24)
    for k in range(4):
        tb = bt + k*SPB
        if tb >= DUR: break
        base = NOTE[arp[k]] * 2.0
        note(tb, base, SPB*0.9, kind='square', gain=lead_gain*0.5, a=0.004, d=0.04, s=0.6, r=0.1)
        note(tb, base, SPB*0.9, kind='tri', gain=lead_gain, a=0.004, d=0.04, s=0.6, r=0.1, detune=0.004)

# --- hits synced to the film ---
# swarm "uh-oh" descending blips ~2.6s
for i,f in enumerate([NOTE['E4'],NOTE['D4'],NOTE['C4']]):
    note(2.6+i*0.18, f, 0.16, kind='square', gain=0.18, a=0.003, d=0.03, s=0.4, r=0.05)
# riser into hero entry (~6.1 -> 7.0)
riser(6.1, dur=0.95, gain=0.34)
# POW impact at 7.0
boom(7.0, gain=1.0); crash(7.0, gain=0.5)
# triumphant stab chord at impact (G major, bright)
for f in [NOTE['G4'],NOTE['B4'],NOTE['D5'],NOTE['G5']]:
    note(7.0, f, 1.1, kind='tri', gain=0.16, a=0.004, d=0.1, s=0.6, r=0.4)
# sustained hero chord ~10.0 (the save)
for f in [NOTE['G4'],NOTE['B4'],NOTE['D5']]:
    note(10.0, f, 2.2, kind='tri', gain=0.12, a=0.02, d=0.2, s=0.7, r=0.8)
# final sting at end card ~13.2 (resolve to G) + little shimmer
crash(13.2, gain=0.4, dur=1.6)
for f in [NOTE['G4'],NOTE['B4'],NOTE['D5'],NOTE['G5']]:
    note(13.2, f, 2.4, kind='tri', gain=0.14, a=0.01, d=0.2, s=0.65, r=1.0)

# --- master: gentle high-pass-ish DC removal, soft limit, normalize ---
buf -= np.mean(buf)
peak = np.max(np.abs(buf)) + 1e-9
buf = buf / peak
buf = np.tanh(buf * 1.4) / math.tanh(1.4)   # soft saturation/limit
buf *= 0.89
# fade in/out
fi, fo = int(0.03*SR), int(0.5*SR)
buf[:fi] *= np.linspace(0,1,fi); buf[-fo:] *= np.linspace(1,0,fo)

out = (buf * 32767).astype(np.int16)
path = sys.argv[1] if len(sys.argv) > 1 else 'music.wav'
with wave.open(path, 'w') as w:
    w.setnchannels(1); w.setsampwidth(2); w.setframerate(SR)
    w.writeframes(out.tobytes())
print(f'wrote {path}  {DUR}s  peak={np.max(np.abs(buf)):.3f}')
