#!/usr/bin/env python3
# 15s score for the "AI is hacking you -> Blanktick resolve" vertical ad.
# Ominous cyber build (0-7) -> EMP impact at 7.0 -> calm resolve (7.3-15).
# Pure numpy, offline. 44.1k mono WAV.
import sys, wave, math
import numpy as np
SR, DUR = 44100, 15.0
N = int(SR*DUR); buf = np.zeros(N)
def idx(t): return int(t*SR)
def add(t, sig, g=1.0):
    i=idx(t); j=min(N,i+len(sig))
    if i<N: buf[i:j]+=sig[:j-i]*g
def osc(f,d,k='sine'):
    n=int(d*SR); t=np.arange(n)/SR; ph=2*np.pi*f*t
    if k=='sine': return np.sin(ph)
    if k=='tri': return 2/np.pi*np.arcsin(np.sin(ph))
    if k=='square': return np.sign(np.sin(ph))*0.8
    if k=='saw': return 2*(t*f-np.floor(0.5+t*f))
    return np.sin(ph)
def envx(n,a=0.005,d=0.05,s=0.7,r=0.08):
    an,dn,rn=int(a*SR),int(d*SR),int(r*SR); e=np.ones(n)
    if an>0:e[:an]=np.linspace(0,1,an)
    if dn>0 and an+dn<n:e[an:an+dn]=np.linspace(1,s,dn)
    if an+dn<n:e[an+dn:]=s
    if rn>0 and rn<n:e[-rn:]*=np.linspace(1,0,rn)
    return e
def note(t,f,d,k='tri',g=0.3,a=0.005,dd=0.05,s=0.7,r=0.08):
    w=osc(f,d,k); add(t,w*envx(len(w),a,dd,s,r),g)
def kick(t,g=0.9):
    n=int(0.2*SR); tt=np.arange(n)/SR; f=120*np.exp(-tt*26)+42
    add(t,np.sin(2*np.pi*np.cumsum(f)/SR)*np.exp(-tt*13),g)
def noise(t,d,g,decay=30,seed=1):
    n=int(d*SR); w=(np.random.default_rng(seed).random(n)*2-1)*np.exp(-np.arange(n)/SR*decay); add(t,w,g)
def riser(t,d=1.5,g=0.3):
    n=int(d*SR); tt=np.arange(n)/SR; f=140*np.power(10,tt/d*1.2)
    w=np.sin(2*np.pi*np.cumsum(f)/SR); rng=np.random.default_rng(5)
    w=0.6*w+0.4*(rng.random(n)*2-1); w*=np.linspace(0.15,1,n); add(t,w*np.exp(-np.maximum(0,tt-d+0.1)*8),g)
def boom(t,g=1.0):
    n=int(0.7*SR); tt=np.arange(n)/SR; f=95*np.exp(-tt*7)+34
    add(t,np.sin(2*np.pi*np.cumsum(f)/SR)*np.exp(-tt*4.5),g)
def bell(t,f,d=1.6,g=0.3):
    n=int(d*SR); tt=np.arange(n)/SR
    w=(np.sin(2*np.pi*f*tt)+0.5*np.sin(2*np.pi*2*f*tt)+0.25*np.sin(2*np.pi*3.01*f*tt))
    add(t,w*np.exp(-tt*3.2),g)
def pad(t,freqs,d=3.0,g=0.14):
    n=int(d*SR); tt=np.arange(n)/SR; w=np.zeros(n)
    for f in freqs: w+=osc(f,d,'tri')+0.5*osc(f*1.005,d,'saw')
    w/=len(freqs); e=np.ones(n); an=int(0.25*SR); e[:an]=np.linspace(0,1,an); e[-int(0.6*SR):]*=np.linspace(1,0,int(0.6*SR))
    add(t,w*e,g)
def hz(semis): return 440.0*(2**(semis/12.0))
NT={'A1':hz(-36),'A2':hz(-24),'C3':hz(-21),'E3':hz(-17),'A3':hz(-12),'C4':hz(-9),'E4':hz(-5),'G3':hz(-14),
    'C5':hz(3),'E5':hz(7),'G5':hz(10),'A4':hz(0),'A5':hz(12),'D4':hz(-7),'B4':hz(2),'D5':hz(5),'G4':hz(-2)}
SPB=0.5
# ---- 0-7 ominous hack build (A minor) ----
for b in range(14):
    tb=b*SPB
    if tb>=7.0: break
    kick(tb, g=0.7+0.02*b)
    # driving bass 8ths A
    for k in range(2):
        note(tb+k*SPB/2, NT['A1']*(1 if k==0 else 2), SPB*0.45,'saw',g=0.18,a=0.003,dd=0.05,s=0.5,r=0.04)
    # dark arp every beat
    arp=[NT['A3'],NT['C4'],NT['E4'],NT['A3']][b%4]
    note(tb, arp, SPB*0.8,'square',g=0.07,a=0.003,dd=0.03,s=0.5,r=0.1)
    # hat
    noise(tb+SPB/2,0.04,0.09,90,seed=b+1)
# alarm two-tone blips every 1s
for k in range(6):
    tt=1.0+k*1.0
    if tt>=6.0: break
    note(tt, hz(4), 0.12,'square',g=0.12,a=0.002,dd=0.02,s=0.5,r=0.03)
    note(tt+0.14, hz(-1), 0.12,'square',g=0.12,a=0.002,dd=0.02,s=0.5,r=0.03)
# glitch noise bursts
for k,s in enumerate([2.3,3.7,4.6,5.2]):
    noise(s,0.08,0.14,40,seed=100+k)
# riser into impact
riser(5.5,1.5,0.32)
# ---- 7.0 EMP impact ----
boom(7.0,1.0); noise(7.0,1.2,0.5,4,seed=7)        # whoosh
bell(7.05, NT['A5'], 1.8, 0.33)                    # the tick chime
# brief drop (silence ~0.25s is just absence of notes)
# ---- 7.4-15 calm resolve (C major, warm) ----
pad(7.5,[NT['C3'],NT['E3'],NT['G3'],NT['C4']],3.4,0.15)
pad(10.6,[NT['C3'],NT['G3'],NT['C4'],NT['E4']],4.2,0.15)
# gentle kelp chime arpeggio
for k,f in enumerate([NT['C5'],NT['E5'],NT['G5'],NT['E5'],NT['C5']]):
    bell(8.0+k*0.5, f, 1.4, 0.16)
# soft final sting on end card ~11.2
bell(11.2, NT['C5'], 2.6, 0.2); bell(11.2, NT['G5'], 2.6, 0.12)
# master
buf-=np.mean(buf); buf/= (np.max(np.abs(buf))+1e-9)
buf=np.tanh(buf*1.3)/math.tanh(1.3); buf*=0.9
fi,fo=int(0.03*SR),int(0.5*SR); buf[:fi]*=np.linspace(0,1,fi); buf[-fo:]*=np.linspace(1,0,fo)
out=(buf*32767).astype(np.int16)
p=sys.argv[1] if len(sys.argv)>1 else 'music_hack.wav'
with wave.open(p,'w') as w: w.setnchannels(1); w.setsampwidth(2); w.setframerate(SR); w.writeframes(out.tobytes())
print(f'wrote {p} {DUR}s')
