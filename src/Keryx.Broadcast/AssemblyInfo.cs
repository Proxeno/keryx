using System.Runtime.CompilerServices;

// The integration tests drive the coordinated control-plane send path (SendControlForTest) directly,
// to stress it concurrently with the batched media fan-out over one shared socket.
[assembly: InternalsVisibleTo("Keryx.IntegrationTests")]
