"""Threat-intelligence providers behind one interface (M3, ADR-015).

Nothing in this package runs unless the operator enabled a provider, and nothing here is needed to
get a verdict: the local analysis never waits on it and never depends on it.
"""
