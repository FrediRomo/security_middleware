#!/usr/bin/env python3
"""Top-level runnable relay template (Section 12, Option B).

The canonical, parameterised implementation lives in
``ros2_security.legacy_relay`` so it can also be exposed as the
``ros2 run ros2_security legacy_relay`` console entry point.  This thin wrapper
keeps the spec's ``nodes/legacy_relay.py`` location runnable directly::

    python3 nodes/legacy_relay.py --bridge std_msgs/msg/String /diag_raw /diagnostics
"""

from ros2_security.legacy_relay import main

if __name__ == "__main__":
    main()
