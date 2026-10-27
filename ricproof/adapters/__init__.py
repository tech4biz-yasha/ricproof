# ricproof: RIC control-loop evidence conformance suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Adapters, one per RIC store. Each wraps the store's own write and read
API so the edits are made beneath it and the verdict is the store's own."""
