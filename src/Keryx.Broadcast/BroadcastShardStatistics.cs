namespace Keryx.Broadcast;

/// <summary>
/// A point-in-time snapshot of one socket-pool shard's counters (<c>broadcast-scale.md</c> §2/§4). Taken by
/// <see cref="BroadcastEndpoint.GetShardStatistics"/>; each counter is monotonic for the endpoint's lifetime.
/// </summary>
/// <param name="ShardIndex">0-based index of the shard in the pool (0 .. <c>SocketPoolSize - 1</c>).</param>
/// <param name="SentDatagrams">Media datagrams the kernel accepted from this shard's <see cref="BroadcastEndpoint.SendBatch"/> flushes.</param>
/// <param name="DroppedDatagrams">Media datagrams this shard tail-dropped (same definition as
/// <see cref="BroadcastEndpoint.DroppedDatagrams"/>, which is the sum of this over all shards).</param>
/// <param name="BatchFlushes">Number of non-empty <see cref="BroadcastEndpoint.SendBatch"/> sub-batches this shard flushed.</param>
/// <param name="ControlDatagramsSent">Per-viewer control datagrams (STUN/DTLS/RTCP and per-connection
/// <c>TryForwardRtp</c> media, i.e. everything through the per-datagram seam) sent on this shard's socket
/// without a socket error.</param>
/// <param name="ReceivedDatagrams">Datagrams the kernel delivered on this shard's socket (shows how the
/// kernel's <c>SO_REUSEPORT</c> hash spread inbound traffic; it need not match the send-shard pinning).</param>
public readonly record struct BroadcastShardStatistics(
    int ShardIndex,
    long SentDatagrams,
    long DroppedDatagrams,
    long BatchFlushes,
    long ControlDatagramsSent,
    long ReceivedDatagrams);
