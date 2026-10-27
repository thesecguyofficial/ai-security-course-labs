#!/usr/bin/env python3
"""Course demo (M4, lesson 4.4): the membership inference signal, on a small model you train yourself.

A tiny classifier is trained on 40 made-up records (random numbers, no real people), many passes over the same
data, the way a small fine-tuning set often is. We then compare how confident it is on records it trained on
("members") and on 40 new records from the same source ("non-members"), and try a simple guess:
"if the model is very confident about the right answer, the record was probably in training".
Last, the model only returns a label (no score), and we try again. Standard library only.

    python3 demos/m04/membership_signal.py
"""
import math
import random

random.seed(7)
FEATURES, N = 30, 40


def make_record():
    x = [random.gauss(0, 1) for _ in range(FEATURES)]
    y = 1 if sum(x[:3]) + random.gauss(0, 1.5) > 0 else 0   # a weak real pattern plus noise
    return x, y


members = [make_record() for _ in range(N)]
non_members = [make_record() for _ in range(N)]

w, b = [0.0] * FEATURES, 0.0
sigmoid = lambda z: 1 / (1 + math.exp(-max(-30, min(30, z))))
for epoch in range(2000):                      # many passes over a small set: it starts to memorise
    for x, y in members:
        p = sigmoid(sum(wi * xi for wi, xi in zip(w, x)) + b)
        g = p - y
        w = [wi - 0.05 * g * xi for wi, xi in zip(w, x)]
        b -= 0.05 * g


def confidence_in_true_label(x, y):
    p = sigmoid(sum(wi * xi for wi, xi in zip(w, x)) + b)
    return p if y == 1 else 1 - p


def label_only(x, y):
    p = sigmoid(sum(wi * xi for wi, xi in zip(w, x)) + b)
    return 1.0 if (p > 0.5) == (y == 1) else 0.0


def attack(score, threshold):
    hits = sum(score(x, y) >= threshold for x, y in members) + sum(score(x, y) < threshold for x, y in non_members)
    return hits / (2 * N)


m = sum(confidence_in_true_label(x, y) for x, y in members) / N
n = sum(confidence_in_true_label(x, y) for x, y in non_members) / N
print(f"average confidence in the right answer   members: {m:.3f}   non-members: {n:.3f}")
print(f"guess 'member' when confidence >= 0.99    correct {attack(confidence_in_true_label, 0.99):.0%} of the time (coin flip: 50%)")
print(f"same guess when the API returns a label only   correct {attack(label_only, 1.0):.0%} of the time")
