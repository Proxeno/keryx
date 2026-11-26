#!/bin/bash
# Regenerates the barge-in measurement tones the Chrome interop lane plays.
#
# tone-440.ogg and tone-880.ogg are 1.5 s of a 440 Hz / 880 Hz sine, encoded as 20 ms
# mono Opus packets at 48 kHz. ChromeBargeInInteropTests pumps the 440 Hz packets as the
# "old" generation and the 880 Hz packets as the "new" generation, so the fixture can tell
# from a 440 vs 880 Goertzel ratio which generation the browser is actually playing.
#
# Run from the repository root; requires ffmpeg with libopus.
ffmpeg -f lavfi -i "sine=frequency=440:sample_rate=48000:duration=1.5" -ac 1 -c:a libopus -b:a 32k -frame_duration 20 -application audio tests/Keryx.IntegrationTests/assets/tone-440.ogg
ffmpeg -f lavfi -i "sine=frequency=880:sample_rate=48000:duration=1.5" -ac 1 -c:a libopus -b:a 32k -frame_duration 20 -application audio tests/Keryx.IntegrationTests/assets/tone-880.ogg
