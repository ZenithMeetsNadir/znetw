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
const tcp = @import("tcp.zig");

const TcpServer = @This();

const AtomicBool = std.atomic.Value(bool);

pub const ServerOpenError = tcp.OpenError || posix.BindError || posix.SetSockOptError;
pub const ServerListenError = tcp.ListenError || posix.ListenError || error{NotBound};
pub const ServerAcceptLoopError = std.mem.Allocator.Error || posix.AcceptError || Connection.ConnListenError;

/// represents a single TCP connection accepted by `TcpServer`
pub const Connection = struct {
    pub const ConnListenError = tcp.ListenError || error{NotAlive};
    pub const ConnAcceptError = posix.AcceptError;
    pub const ConnSendError = tcp.SendError || error{NotAlive};

    socket: socket_t,
    client_ip4: Ip4Address,
    alive: AtomicBool,
    listening: AtomicBool = .init(false),
    awaits_disposal: AtomicBool = .init(false),
    listen_th: ?Thread = null,
    server: *TcpServer,

    /// Accepts a new incoming connection on the `TcpServer`'s bound socket.
    /// Blocking or non-blocking depending on the server's socket mode.
    pub fn accept(server: *TcpServer) ConnAcceptError!Connection {
        var client_ip4: Ip4Address = undefined;
        var sock_len: posix.socklen_t = @sizeOf(@TypeOf(client_ip4.sa));
        const flags: u32 = if (!server.blocking) posix.SOCK.NONBLOCK else 0;

        const socket = try posix.accept(server.socket, @ptrCast(&client_ip4.sa), &sock_len, flags);

        return Connection{
            .socket = socket,
            .client_ip4 = client_ip4,
            .alive = .init(true),
            .server = server,
        };
    }

    /// Closes the connection socket and stops the listen thread if running.
    ///
    /// It is safe to call this function more than once.
    pub fn close(self: *Connection) void {
        if (self.listen_th) |th| {
            self.listening.store(false, .release);

            if (self.server.blocking) {
                self.alive.store(false, .release);
                posix.shutdown(self.socket, posix.ShutdownHow.both) catch |err| {
                    std.log.err("tcp server connection socket shutdown error: {s}", .{@errorName(err)});
                    std.log.info("tcp server connection closing socket", .{});
                    posix.close(self.socket);
                };
            }

            th.join();
            self.listen_th = null;
        }

        if (self.alive.load(.acquire)) {
            self.alive.store(false, .release);
            posix.close(self.socket);
        }

        std.log.info("tcp connection from {f} closed", .{self.client_ip4});
    }

    /// Starts listening for incoming data on a dedicated thread. Triggers server defined callback `dispatch_fn` on receive.
    ///
    /// Returns:
    /// `NotAlive` if the connection is not alive.
    /// `AlreadyListening` if the listen thread is already running.
    pub fn listen(self: *Connection) ConnListenError!void {
        if (!self.alive.load(.acquire))
            return ConnListenError.NotAlive;

        if (self.listen_th != null)
            return ConnListenError.AlreadyListening;

        self.listening.store(true, .release);
        errdefer self.listening.store(false, .release);

        self.listen_th = try Thread.spawn(.{}, listenLoop, .{self});

        std.log.info("tcp connection to {f} opened", .{self.client_ip4});
    }

    fn listenLoop(self: *Connection) std.mem.Allocator.Error!void {
        if (self.server.dispatch_fn == null)
            std.log.warn("tcp server dispatch function is not set, incoming data will not be processed", .{});

        const buffer = try self.server.allocator.alloc(u8, self.server.buffer_size);
        defer self.server.allocator.free(buffer);

        while (self.listening.load(.acquire) and self.server.listening.load(.acquire)) {
            const data_len = posix.recv(self.socket, buffer, 0) catch |err| switch (err) {
                posix.RecvFromError.MessageTooBig => tcp.buffer_size,
                else => continue,
            };
            if (data_len == 0) continue;

            if (self.server.dispatch_fn) |dspch| {
                dspch(self, buffer[0..data_len]) catch continue;
            }
        }
    }

    /// Sends data through the `Connection`'s connected socket.
    ///
    /// Returns `NotAlive` if the connection is not alive.
    /// It might immediately return `WouldBlock` for a blocking operation in non-blocking mode.
    pub fn send(self: Connection, data: []const u8) ConnSendError!void {
        if (!self.alive.load(.acquire))
            return ConnSendError.NotAlive;

        const bytes_sent = try posix.write(self.socket, data);

        if (bytes_sent != data.len)
            std.log.warn("tcp server send() inconsistency - number of bytes sent: {d} of {d}.", .{ bytes_sent, data.len });
    }

    /// Labels the connection to be later disposed of. It will be closed and removed from the server's connection list.
    /// Useful when closing the connection from within the dispatch function.
    pub inline fn labelDispose(self: *Connection) void {
        self.awaits_disposal.store(true, .release);
    }
};

/// the number of incoming connections queued up before the kernel starts rejecting new ones
const backlog = 128;

// TcpServer struct
socket: socket_t,
ip4: Ip4Address,
blocking: bool,
bound: AtomicBool,
/// this callback should be written with care, as it will be called from multiple listening connection threads
dispatch_fn: ?*const fn (connection: *Connection, data: []const u8) anyerror!void = null,
listening: AtomicBool = .init(false),
listen_th: ?Thread = null,
connections: std.array_list.Managed(*Connection),
buffer_size: usize,
allocator: std.mem.Allocator,

/// Creates a TCP server and binds to the specified IP and port. Uses a blocking or non-blocking socket.
///
/// If passed `buffer_size` is null, the default buffer size defined in `tcp.buffer_size` is used.
pub fn open(ip: []const u8, port: u16, blocking: bool, buffer_size: ?usize, allocator: std.mem.Allocator) ServerOpenError!TcpServer {
    const socket: socket_t = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
    errdefer posix.close(socket);

    if (!blocking)
        try socket_util.setNonBlocking(socket);

    try socket_util.keepAlive(socket);

    const ip4 = try Ip4Address.parse(ip, port);

    try posix.bind(socket, @ptrCast(&ip4.sa), @sizeOf(addr_in));

    return TcpServer{
        .socket = socket,
        .ip4 = ip4,
        .blocking = blocking,
        .bound = .init(true),
        .connections = .init(allocator),
        .buffer_size = buffer_size orelse tcp.buffer_size,
        .allocator = allocator,
    };
}

/// Closes the TCP server socket and stops the listen thread if running.
///
/// It is safe to call this function more than once.
pub fn close(self: *TcpServer) void {
    if (self.listen_th) |th| {
        self.listening.store(false, .release);

        if (self.blocking) {
            self.bound.store(false, .release);
            posix.shutdown(self.socket, posix.ShutdownHow.both) catch |err| {
                std.log.err("tcp server socket shutdown error: {s}", .{@errorName(err)});
                std.log.info("tcp server closing socket", .{});
                posix.close(self.socket);
            };
        }

        th.join();
        self.listen_th = null;

        const len = self.connections.items.len;
        for (self.connections.items) |conn| {
            conn.close();
            self.allocator.destroy(conn);
        }
        self.connections.deinit();

        std.log.info("all {d} tcp connections closed", .{len});
    }

    if (self.bound.load(.acquire)) {
        self.bound.store(false, .release);
        posix.close(self.socket);
    }

    std.log.info("tcp server shut down", .{});
}

/// Starts listening for incoming connections on a dedicated thread and accepts them.
///
/// Returns:
/// - `NotBound` if the server socket is not bound.
/// - `AlreadyListening` if the listen thread is already running and listening for connections.
pub fn listen(self: *TcpServer) ServerListenError!void {
    if (!self.bound.load(.acquire))
        return ServerListenError.NotBound;

    if (self.listen_th != null)
        return ServerListenError.AlreadyListening;

    self.listening.store(true, .release);
    errdefer self.listening.store(false, .release);

    try posix.listen(self.socket, backlog);

    self.listen_th = try Thread.spawn(.{}, acceptLoop, .{self});

    std.log.info("tcp server listening on {f}...", .{self.ip4});
}

fn acceptLoop(self: *TcpServer) void {
    while (self.listening.load(.acquire)) {
        self.acceptLoopErrorNet() catch {};
        self.closeExpiredConnections();
    }
}

fn acceptLoopErrorNet(self: *TcpServer) ServerAcceptLoopError!void {
    var conn = try Connection.accept(self);
    errdefer conn.close();

    // destroyed when joining the connection thread
    var conn_alloc = try self.allocator.create(Connection);
    errdefer self.allocator.destroy(conn_alloc);
    conn_alloc.* = conn;

    try conn_alloc.listen();

    try self.connections.append(conn_alloc);
}

fn closeExpiredConnections(self: *TcpServer) void {
    var i: usize = 0;

    while (i < self.connections.items.len) {
        if (self.connections.items[i].awaits_disposal.load(.acquire)) {
            var exp_conn = self.connections.swapRemove(i);
            exp_conn.close();
            self.allocator.destroy(exp_conn);
        } else i += 1;
    }
}
