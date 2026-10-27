# ricproof: RIC control-loop evidence conformance suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""ricproof measures whether the stores an Open RAN RIC keeps its decisions,
policies and models in notice tampering. It runs the agmi at-rest edits
(T1 to T10) unchanged against RIC stores through adapters that speak each
store's own API."""

__version__ = "0.2.0"
