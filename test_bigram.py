#!/usr/bin/env python3
"""test_bigram.py — SPTA Bigram Authentication Test Client

Tests three scenarios:
  1. AUTH   — correct bigrams, timing within 2-sigma (mean±50ms)
  2. REJECT — correct bigrams, wildly wrong timing (z >> 3)
  3. REJECT — wrong word (word does not contain bigram letters)
"""
import socket
import random
import sys

HOST = "127.0.0.1"
PORT = 8009

# Enrolled phrase bigrams and their timing parameters
BIGRAMS = ["he", "ll", "ow", "or", "ld"]
MEAN_MS  = 600
SIGMA_MS = 100

def word_has_bigram(word, bg):
    """Check if word contains all letters of bigram."""
    word_up = word.upper()
    a = bg[0].upper()
    b = bg[1].upper() if len(bg) > 1 and bg[1] else None
    has_a = a in word_up
    has_b = (b is None) or (b in word_up)
    return has_a and has_b

def connect_and_get_words():
    """Connect to server, return (sock_file, words_list)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    f = s.makefile('r')

    session_line = f.readline().strip()
    print(f"  {session_line}")

    words_line = f.readline().strip()
    parts = words_line.split()
    assert parts[0] == "WORDS", f"Expected WORDS, got {parts[0]}"
    words = parts[1:]
    print(f"  WORDS received: {len(words)} words")

    ready = f.readline().strip()
    assert ready == "READY", f"Expected READY, got {ready}"
    print(f"  {ready}")

    return s, f, words

def read_result(f):
    """Read RESULT and optional DETAIL lines."""
    result = f.readline().strip()
    detail = f.readline().strip()
    return result, detail

def find_bigram_word(words, bg):
    """Find first word index where word contains both bigram letters."""
    for i, w in enumerate(words):
        if word_has_bigram(w, bg):
            return i
    return None

def find_wrong_word(words, bg):
    """Find first word index where word does NOT contain both bigram letters."""
    for i, w in enumerate(words):
        if not word_has_bigram(w, bg):
            return i
    return None

# ===================================================================
print("=" * 60)
print("TEST 1: AUTH — correct bigrams, normal timing (mean±50ms)")
print("=" * 60)
try:
    sock, f, words = connect_and_get_words()
    raw = sock.makefile('w')

    for bi, bg in enumerate(BIGRAMS):
        idx = find_bigram_word(words, bg)
        if idx is None:
            print(f"  ERROR: no word found for bigram '{bg}'!")
            sys.exit(1)
        ms = MEAN_MS + random.randint(-50, 50)
        word = words[idx]
        print(f"  PRESS bigram[{bi}]='{bg}' word[{idx}]='{word}' ms={ms}")
        sock.sendall(f"PRESS {idx} {ms}\n".encode())

    sock.sendall(b"DONE\n")
    result, detail = read_result(f)
    print(f"  -> {result}")
    print(f"  -> {detail}")
    status1 = "AUTH" in result
    sock.close()
except Exception as e:
    print(f"  ERROR: {e}")
    status1 = False

print()

# ===================================================================
print("=" * 60)
print("TEST 2: REJECT — correct bigrams, wildly wrong timing (z~15)")
print("=" * 60)
try:
    sock, f, words = connect_and_get_words()

    for bi, bg in enumerate(BIGRAMS):
        idx = find_bigram_word(words, bg)
        if idx is None:
            print(f"  ERROR: no word found for bigram '{bg}'!")
            sys.exit(1)
        # timing = mean + 15*sigma → z = 15, way beyond 3-sigma reject
        ms = MEAN_MS + 15 * SIGMA_MS
        word = words[idx]
        print(f"  PRESS bigram[{bi}]='{bg}' word[{idx}]='{word}' ms={ms} (z=15!)")
        sock.sendall(f"PRESS {idx} {ms}\n".encode())

    sock.sendall(b"DONE\n")
    result, detail = read_result(f)
    print(f"  -> {result}")
    print(f"  -> {detail}")
    status2 = "REJECT" in result
    sock.close()
except Exception as e:
    print(f"  ERROR: {e}")
    status2 = False

print()

# ===================================================================
print("=" * 60)
print("TEST 3: REJECT — wrong word (bigram letters not in word)")
print("=" * 60)
try:
    sock, f, words = connect_and_get_words()

    # For the first bigram, pick a word that does NOT contain both letters
    bi = 0
    bg = BIGRAMS[0]
    wrong_idx = find_wrong_word(words, bg)
    if wrong_idx is None:
        print(f"  WARN: all words contain bigram '{bg}', using valid word anyway")
        wrong_idx = find_bigram_word(words, bg)

    word = words[wrong_idx]
    ms = MEAN_MS
    print(f"  PRESS bigram[0]='{bg}' word[{wrong_idx}]='{word}' ms={ms}")
    print(f"  (word has_bigram={word_has_bigram(word, bg)} — expect False)")
    sock.sendall(f"PRESS {wrong_idx} {ms}\n".encode())
    sock.sendall(b"DONE\n")

    result, detail = read_result(f)
    print(f"  -> {result}")
    print(f"  -> {detail}")
    status3 = "REJECT" in result
    sock.close()
except Exception as e:
    print(f"  ERROR: {e}")
    status3 = False

print()

# ===================================================================
print("=" * 60)
print("TEST 4: AUTH — ALL bigrams verified, print z-scores")
print("=" * 60)
try:
    sock, f, words = connect_and_get_words()

    timings = []
    for bi, bg in enumerate(BIGRAMS):
        idx = find_bigram_word(words, bg)
        # tight timing: mean ± 30ms (z < 0.3, very safe)
        ms = MEAN_MS + random.randint(-30, 30)
        timings.append((bi, bg, idx, words[idx], ms))
        z = abs(ms - MEAN_MS) / SIGMA_MS
        print(f"  bi={bi} bg='{bg}' word='{words[idx]}' ms={ms} z={z:.2f}")
        sock.sendall(f"PRESS {idx} {ms}\n".encode())

    sock.sendall(b"DONE\n")
    result, detail = read_result(f)
    print(f"  -> {result}")
    print(f"  -> {detail}")
    status4 = "AUTH" in result
    sock.close()
except Exception as e:
    print(f"  ERROR: {e}")
    status4 = False

print()
print("=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"  Test 1 (AUTH normal timing):   {'PASS' if status1 else 'FAIL'}")
print(f"  Test 2 (REJECT bad timing):    {'PASS' if status2 else 'FAIL'}")
print(f"  Test 3 (REJECT wrong word):    {'PASS' if status3 else 'FAIL'}")
print(f"  Test 4 (AUTH tight timing):    {'PASS' if status4 else 'FAIL'}")

all_pass = status1 and status2 and status3 and status4
print()
print("ALL TESTS PASSED" if all_pass else "SOME TESTS FAILED")
sys.exit(0 if all_pass else 1)
