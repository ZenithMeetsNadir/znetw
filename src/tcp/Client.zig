const std = @import("std");
const builtin = @import("builtin");
const net = std.net;
const mem = std.mem;
const posix = std.posix;
const addr_in = posix.sockaddr.in;
const socket_t = posix.socket_t;
const Ip4Address = net.Ip4Address;
const Thread = std.Thread;
const windows = std.os.windows;
const util = @import("util");
const socket_util = util.socket;
const TcpServer = @import("Server.zig");
const tcp = @import("tcp.zig");

const log = std.log.scoped(.TcpClient);

const TcpClient = @This();

const AtomicBool = std.atomic.Value(bool);

pub const ClientConnectError = tcp.OpenError || posix.ConnectError;
pub const ClientListenError = tcp.ListenError || error{NotConnected};
pub const ClientSendError = tcp.SendError || error{NotConnected};

socket: socket_t,
ip4: net.Ip4Address,
blocking: bool,
connected: AtomicBool,
/// this callback should be written with care, as it will be called from the listen thread
dispatch_fn: ?*const fn (self: *const TcpClient, data: []const u8) anyerror!void = null,
listening: AtomicBool = .init(false),
listen_th: ?Thread = null,
recv_buffer: []u8,

/// Creates a TCP client and connects to the specified IP and port. Uses a blocking or non-blocking socket.
///
/// If passed `buffer_size` is null, the default buffer size defined in `tcp.buffer_size` is used.
pub fn connect(ip: []const u8, port: u16, blocking: bool, recv_buffer: []u8) ClientConnectError!TcpClient {
    const socket: socket_t = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    errdefer posix.close(socket);

    if (!blocking)
        try socket_util.setNonBlocking(socket);

    const ip4 = try Ip4Address.parse(ip, port);

    posix.connect(socket, @ptrCast(&ip4.sa), @sizeOf(addr_in)) catch |err| switch (err) {
        posix.ConnectError.WouldBlock => if (blocking) return err,
        else => return err,
    };

    return TcpClient{
        .socket = socket,
        .ip4 = ip4,
        .blocking = blocking,
        .connected = .init(true),
        .recv_buffer = recv_buffer,
    };
}

/// closes the TCP client socket and stops the listen thread if running.
///
/// It is safe to call this function more than once.
pub fn close(self: *TcpClient) void {
    if (self.listen_th) |th| {
        self.listening.store(false, .release);

        if (self.blocking) {
            self.connected.store(false, .release);
            posix.shutdown(self.socket, posix.ShutdownHow.both) catch |err| {
                log.warn("failed to shutdown socket properly due to error: {s}", .{@errorName(err)});
                log.info("closing socket", .{});
                posix.close(self.socket);
            };
        }

        th.join();
        self.listen_th = null;
    }

    if (self.connected.load(.acquire)) {
        self.connected.store(false, .release);
        posix.close(self.socket);
    }

    log.info("shut down", .{});
}

/// Starts listening for incoming data on a dedicated thread.
///
/// Returns:
/// - `NotConnected` if the client is not connected.
/// - `AlreadyListening` if the listen thread is already running.
pub fn listen(self: *TcpClient, allocator: std.mem.Allocator) ClientListenError!void {
    if (!self.connected.load(.acquire))
        return ClientListenError.NotConnected;

    if (self.listen_th != null)
        return ClientListenError.AlreadyListening;

    self.listening.store(true, .release);
    errdefer self.listening.store(false, .release);

    self.listen_th = try Thread.spawn(.{}, listenLoop, .{ self, allocator });

    log.info("running...", .{});
}

fn listenLoop(self: *const TcpClient) void {
    if (self.dispatch_fn == null)
        log.warn("dispatch function is not set, incoming data will not be processed", .{});

    while (self.listening.load(.acquire)) {
        const data_len = posix.recv(self.socket, self.recv_buffer, 0) catch |err| switch (err) {
            posix.RecvFromError.MessageTooBig => self.recv_buffer.len,
            else => continue,
        };
        if (data_len == 0) continue;

        if (self.dispatch_fn) |dspch| {
            dspch(self, self.recv_buffer[0..data_len]) catch continue;
        }
    }
}

/// Sends data through the connected socket.
///
/// Returns `NotConnected` if the client is not connected.
/// It might immediately return `WouldBlock` for a blocking operation in non-blocking mode.
pub fn send(self: TcpClient, data: []const u8) ClientSendError!void {
    if (!self.connected.load(.acquire))
        return ClientSendError.NotConnected;

    const bytes_sent = try posix.write(self.socket, data);

    if (bytes_sent != data.len)
        log.warn("send() inconsistency - number of bytes sent: {d} of {d}", .{ bytes_sent, data.len });
}
