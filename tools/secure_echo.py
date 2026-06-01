#!/usr/bin/env python3
"""Top-level runnable debug-echo template (Section 11).

The canonical implementation lives in ``ros2_security.secure_echo`` so it can be
exposed as the ``ros2 run ros2_security secure_echo`` console entry point.  This
thin wrapper keeps the spec's ``tools/secure_echo.py`` location runnable
directly::

    python3 tools/secure_echo.py --topic /camera/frame --type sensor_msgs/msg/Image
"""

from ros2_security.secure_echo import main

if __name__ == "__main__":
    main()
