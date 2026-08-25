using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Keryx.Dtls.Tests")]

// Keryx composes DtlsConfig from PeerConnectionConfig, and the Chrome-interop DTLS suite/curve
// matrix forces a specific suite or curve through that same path to exercise it against a real
// browser. Both accesses are internal-only test/interop plumbing, not part of the public surface.
[assembly: InternalsVisibleTo("Keryx")]
[assembly: InternalsVisibleTo("Keryx.IntegrationTests")]
