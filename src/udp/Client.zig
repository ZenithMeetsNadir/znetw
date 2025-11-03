const std = @import("std");
const net = std.net;
const mem = std.mem;
const posix = std.posix;
const in = posix.sockaddr.in;
const socket_t = posix.socket_t;
const Ip4Address = net.Ip4Address;
const Thread = std.Thread;
const util = @import("util");
const socket_util = util.socket;
const udp = @import("udp.zig");

const UdpServer = @import("Server.zig");
const UdpClient = @This();

pub const ClientConnectError = udp.OpenError || posix.ConnectError;
pub const ClientListenError = udp.ListenError || error{NotConnected};
pub const ClientSendError = udp.SendError || error{NotConnected};

udp_core: UdpServer,
dispatch_fn: ?*const fn (self: *const UdpClient, data: []const u8) anyerror!void = null,

/// Creates a UDP client and connects the datagram socket address to the specified IP and port. Uses a blocking or non-blocking socket.
///
/// If passed `buffer_size` is null, the default buffer size defined in `udp.buffer_size` is used.
pub fn connect(ip: []const u8, port: u16, blocking: bool, buffer_size: ?usize, allocator: std.mem.Allocator) ClientConnectError!UdpClient {
    const socket: socket_t = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    errdefer posix.close(socket);

    try socket_util.setNonBlocking(socket);

    const ip4 = try Ip4Address.parse(ip, port);

    posix.connect(socket, @ptrCast(&ip4.sa), @sizeOf(in)) catch |err| switch (err) {
        posix.ConnectError.WouldBlock => {},
        else => return err,
    };

    return UdpClient{ .udp_core = UdpServer{
        .socket = socket,
        .ip4 = ip4,
        .blocking = blocking,
        .bound = .init(true),
        .buffer_size = buffer_size orelse udp.buffer_size,
        .allocator = allocator,
    } };
}

/// Closes the UDP client socket and stops the serving thread if running.
///
/// It is safe to call this function more than once.
pub inline fn close(self: *UdpClient) void {
    self.udp_core.close();
}

/// Starts listening for incoming data on a dedicated thread.
///
/// Returns:
/// - `NotConnected` if the client is not connected.
/// - `AlreadyListening` if the listen thread is already running.
pub fn listen(self: *UdpClient) ClientListenError!void {
    if (!self.udp_core.bound.load(.acquire))
        return ClientListenError.NotConnected;

    if (self.udp_core.serve_th != null)
        return ClientListenError.AlreadyListening;

    self.udp_core.listening.store(true, .release);
    errdefer self.udp_core.listening.store(false, .release);

    self.udp_core.serve_th = try Thread.spawn(.{}, listenLoop, .{self});

    std.log.info("udp client running...", .{});
}

fn listenLoop(self: *const UdpClient) std.mem.Allocator.Error!void {
    if (self.dispatch_fn == null)
        std.log.warn("udp server dispatch function is not set, incoming data will not be processed", .{});

    const buffer = try self.udp_core.allocator.alloc(u8, self.udp_core.buffer_size);
    defer self.udp_core.allocator.free(buffer);

    while (self.udp_core.listening.load(.acquire)) {
        const data_len = posix.recv(self.udp_core.socket, buffer, 0) catch |err| switch (err) {
            posix.RecvFromError.MessageTooBig => self.udp_core.buffer_size,
            else => continue,
        };
        if (data_len == 0) continue;

        if (self.dispatch_fn) |dspch| {
            dspch(self, buffer[0..data_len]) catch continue;
        }
    }
}

/// Sends data through the connected socket.
///
/// Returns `NotConnected` if the client is not connected.
/// It might immediately return `WouldBlock` for a blocking operation in non-blocking mode.
pub fn send(self: UdpClient, data: []const u8) ClientSendError!void {
    if (!self.udp_core.bound.load(.acquire))
        return ClientSendError.NotConnected;

    const bytes_sent = try posix.write(self.udp_core.socket, data);

    if (bytes_sent != data.len)
        std.log.warn("udp client send() inconsistency - number of bytes sent: {d} of {d}", .{ bytes_sent, data.len });
}
