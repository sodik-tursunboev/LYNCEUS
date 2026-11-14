"""Learned models (AI1 P1): judgment that is fitted to data, not written by hand.

The first one reads only the host name of a URL. E1's legitimate URLs are almost all bare home
pages and its phishing URLs mostly have paths, so a model that saw paths would learn "a path means
phishing" and flag ordinary browsing; reading the host only removes that shortcut. Training and
measurement live in `eval/learn_url.py`; the runtime here is pure Python and reads a weights file.
"""
