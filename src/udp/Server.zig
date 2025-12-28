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
const udp = @import("udp.zig");

const log = std.log.scoped(.UdpCore);

const UdpServer = @This();

const AtomicBool = std.atomic.Value(bool);

pub const ServerOpenError = udp.OpenError || posix.BindError;
pub const ServerListenError = udp.ListenError || error{NotBound};
pub const ServerSendToError = udp.SendError || posix.SendToError || error{NotBound};

socket: socket_t,
ip4: net.Ip4Address,
blocking: bool = false,
bound: AtomicBool,
dispatch_fn: ?*const fn (server: *const UdpServer, sender_addr: Ip4Address, data: []const u8) anyerror!void = null,
listening: AtomicBool = .init(false),
serve_th: ?Thread = null,
recv_buffer: []u8,

/// Creates a UDP server and binds to the specified IP and port. Uses a blocking or non-blocking socket.
///
/// If `buffer_size` is null, the default buffer size defined in `udp.buffer_size` is used.
pub fn open(ip: []const u8, port: u16, blocking: bool, recv_buffer: []u8) ServerOpenError!UdpServer {
    const socket: socket_t = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    errdefer posix.close(socket);

    if (!blocking)
        try socket_util.setNonBlocking(socket);

    const ip4 = try Ip4Address.parse(ip, port);

    try posix.bind(socket, @ptrCast(&ip4.sa), @sizeOf(addr_in));

    return UdpServer{
        .socket = socket,
        .ip4 = ip4,
        .recv_buffer = recv_buffer,
        .blocking = blocking,
        .bound = .init(true),
    };
}

/// Closes the UDP server socket and stops the serving thread if running.
///
/// It is safe to call this function more than once.
pub fn close(self: *UdpServer) void {
    if (self.serve_th) |th| {
        self.listening.store(false, .release);

        if (self.blocking) {
            self.bound.store(false, .release);
            posix.shutdown(self.socket, .both) catch |err| {
                log.warn("failed to shutdown socket properly due to error: {s}", .{@errorName(err)});
                log.info("closing socket", .{});
                posix.close(self.socket);
            };
        }

        th.join();
        self.serve_th = null;
    }

    if (self.bound.load(.acquire)) {
        self.bound.store(false, .release);
        posix.close(self.socket);
    }

    log.info("shut down", .{});
}

/// Starts listening for incoming data on a dedicated thread. Triggers callback `dispatch_fn` on receive.
///
/// Returns:
/// - `NotBound` if the server socket is not bound.
/// - `AlreadyListening` if the listen thread is already running.
pub fn listen(self: *UdpServer) ServerListenError!void {
    if (!self.bound.load(.acquire))
        return ServerListenError.NotBound;

    if (self.serve_th != null)
        return ServerListenError.AlreadyListening;

    self.listening.store(true, .release);
    errdefer self.listening.store(false, .release);

    self.serve_th = try Thread.spawn(.{}, listenLoop, .{self});

    log.info("listening on {f}...", .{self.ip4});
}

fn listenLoop(self: *UdpServer) void {
    if (self.dispatch_fn == null)
        log.warn("dispatch function is not set, incoming data will not be processed", .{});

    while (self.listening.load(.acquire)) {
        var sender_ip4: Ip4Address = undefined;
        var addr_len: posix.socklen_t = @sizeOf(addr_in);

        const data_len = posix.recvfrom(self.socket, self.recv_buffer, 0, @ptrCast(&sender_ip4.sa), &addr_len) catch |err| switch (err) {
            posix.RecvFromError.MessageTooBig => self.recv_buffer.len,
            else => continue,
        };
        if (data_len == 0) continue;

        if (self.dispatch_fn) |dspch| {
            dspch(self, sender_ip4, self.recv_buffer[0..data_len]) catch continue;
        }
    }
}

/// Sends data through the bound socket to the specified address.
///
/// Returns:
/// - Number of bytes sent. If bytes sent is less than `data.len`, the caller can call this function again on the remaining data.
/// - `NotBound` if the server socket is not bound.
/// Even though `sendTo` could utilize a different socket, the function will call `sendTo` on the server bound socket, hence returning `NotBound` if the socket is not bound.
/// - `WouldBlock` for a blocking operation in non-blocking mode.
pub inline fn sendTo(self: UdpServer, ip4: Ip4Address, data: []const u8) ServerSendToError!usize {
    if (!self.bound.load(.acquire))
        return ServerSendToError.NotBound;

    return posix.sendto(self.socket, data, 0, @ptrCast(&ip4.sa), @sizeOf(addr_in));
}

/// Blocks until all data has been sent through the connected socket.
///
/// Returns `NotBound` if the server socket is not bound.
/// Even though `sendTo` could utilize a different socket, the function will call `sendTo` on the server bound socket, hence returning `NotBound` if the socket is not bound.
pub fn sendAllTo(self: UdpServer, ip4: Ip4Address, data: []const u8) ServerSendToError!void {
    if (!self.bound.load(.acquire))
        return ServerSendToError.NotBound;

    var total_sent: usize = 0;
    while (total_sent < data.len) {
        total_sent += self.sendTo(ip4, data[total_sent..]) catch |err| switch (err) {
            ServerSendToError.WouldBlock => {
                Thread.yield() catch continue;
                continue;
            },
            else => return err,
        };
    }
}

/// Attempts to enable broadcast on the server socket.
pub inline fn enableBroadcast(self: UdpServer) posix.SetSockOptError!void {
    const enable: c_int = 1;
    try posix.setsockopt(self.socket, posix.SOL.SOCKET, posix.SO.BROADCAST, std.mem.asBytes(&enable));
}
