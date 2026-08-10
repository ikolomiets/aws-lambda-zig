const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const Scanner = std.json.Scanner;
const json = @import("../utils/json.zig");
const KeyVal = @import("../utils/KeyVal.zig");

pub const Event = struct {
    records: []const Record,

    pub fn deinit(self: Event, gpa: Allocator) void {
        for (self.records) |record| record.deinit(gpa);
        gpa.free(self.records);
    }
};

pub const Record = struct {
    message_id: []const u8,
    receipt_handle: []const u8,
    body: []const u8,
    attributes: []const KeyVal = &.{},
    message_attributes: []const MessageAttribute = &.{},
    md5_of_body: ?[]const u8 = null,
    md5_of_message_attributes: ?[]const u8 = null,
    event_source: []const u8,
    event_source_arn: []const u8,
    aws_region: []const u8,

    fn deinit(self: Record, gpa: Allocator) void {
        const builder: RecordBuilder = .{
            .message_id = self.message_id,
            .receipt_handle = self.receipt_handle,
            .body = self.body,
            .attributes = self.attributes,
            .message_attributes = self.message_attributes,
            .md5_of_body = self.md5_of_body,
            .md5_of_message_attributes = self.md5_of_message_attributes,
            .event_source = self.event_source,
            .event_source_arn = self.event_source_arn,
            .aws_region = self.aws_region,
        };
        builder.deinit(gpa);
    }
};

pub const MessageAttribute = struct {
    name: []const u8,
    value: MessageAttributeValue,
    custom_type: ?[]const u8 = null,

    fn init(gpa: Allocator, scanner: *Scanner, name: []const u8) !MessageAttribute {
        var data_type: ?[]const u8 = null;
        var string_value: ?[]const u8 = null;
        var binary_value: ?[]const u8 = null;
        var string_list_values: ?[]const []const u8 = null;
        var binary_list_values: ?[]const []const u8 = null;
        var saw_string_value = false;
        var saw_binary_value = false;
        var saw_data_type = false;
        errdefer {
            gpa.free(name);
            if (data_type) |s| gpa.free(s);
            if (string_value) |s| gpa.free(s);
            if (binary_value) |s| gpa.free(s);
            if (string_list_values) |list| freeStringList(gpa, list);
            if (binary_list_values) |list| freeStringList(gpa, list);
        }

        var it = try json.ObjectIterator.init(gpa, scanner);
        defer it.deinit();
        while (try it.next()) |key| {
            if (mem.eql(u8, "stringValue", key)) {
                if (saw_string_value) return json.inputError();
                saw_string_value = true;
                string_value = try json.nextStringOptional(scanner, gpa);
            } else if (mem.eql(u8, "binaryValue", key)) {
                if (saw_binary_value) return json.inputError();
                saw_binary_value = true;
                binary_value = try json.nextStringOptional(scanner, gpa);
            } else if (mem.eql(u8, "stringListValues", key)) {
                if (string_list_values != null) return json.inputError();
                string_list_values = try nextStringList(gpa, scanner);
            } else if (mem.eql(u8, "binaryListValues", key)) {
                if (binary_list_values != null) return json.inputError();
                binary_list_values = try nextStringList(gpa, scanner);
            } else if (mem.eql(u8, "dataType", key)) {
                if (saw_data_type) return json.inputError();
                saw_data_type = true;
                data_type = try json.nextString(scanner, gpa);
            } else {
                try scanner.skipValue();
            }
        }

        if (string_list_values) |list| {
            if (list.len != 0) return json.inputError();
        }
        if (binary_list_values) |list| {
            if (list.len != 0) return json.inputError();
        }

        const parsed_type = parseMessageAttributeType(data_type orelse return json.inputError()) catch
            return json.inputError();
        const custom_type = if (parsed_type.custom_type) |custom|
            try gpa.dupe(u8, custom)
        else
            null;
        errdefer if (custom_type) |custom| gpa.free(custom);

        const value: MessageAttributeValue = switch (parsed_type.value_type) {
            .string => .{ .string = string_value orelse return json.inputError() },
            .number => .{ .number = string_value orelse return json.inputError() },
            .binary_base64 => .{ .binary_base64 = binary_value orelse return json.inputError() },
        };
        switch (parsed_type.value_type) {
            .string, .number => if (binary_value != null) return json.inputError(),
            .binary_base64 => if (string_value != null) return json.inputError(),
        }

        gpa.free(data_type.?);
        data_type = null;
        if (string_list_values) |list| freeStringList(gpa, list);
        string_list_values = null;
        if (binary_list_values) |list| freeStringList(gpa, list);
        binary_list_values = null;

        return .{
            .name = name,
            .value = value,
            .custom_type = custom_type,
        };
    }

    fn deinit(self: MessageAttribute, gpa: Allocator) void {
        gpa.free(self.name);
        switch (self.value) {
            inline else => |value| gpa.free(value),
        }
        if (self.custom_type) |custom| gpa.free(custom);
    }
};

pub const MessageAttributeValue = union(enum) {
    string: []const u8,
    number: []const u8,
    binary_base64: []const u8,
};

const ParsedMessageAttributeType = struct {
    value_type: std.meta.Tag(MessageAttributeValue),
    custom_type: ?[]const u8,
};

fn parseMessageAttributeType(data_type: []const u8) !ParsedMessageAttributeType {
    const types = .{
        .{ "String", std.meta.Tag(MessageAttributeValue).string },
        .{ "Number", std.meta.Tag(MessageAttributeValue).number },
        .{ "Binary", std.meta.Tag(MessageAttributeValue).binary_base64 },
    };

    inline for (types) |entry| {
        const base, const value_type = entry;
        if (mem.eql(u8, data_type, base)) {
            return .{ .value_type = value_type, .custom_type = null };
        }
        if (mem.startsWith(u8, data_type, base) and data_type.len > base.len and
            data_type[base.len] == '.')
        {
            const custom_type = data_type[base.len + 1 ..];
            if (custom_type.len == 0) return error.InvalidMessageAttributeType;
            return .{ .value_type = value_type, .custom_type = custom_type };
        }
    }

    return error.InvalidMessageAttributeType;
}

pub const BatchItemFailure = struct {
    item_identifier: []const u8,
};

pub const Response = struct {
    batch_item_failures: []const BatchItemFailure = &.{},
};

pub fn parseEvent(gpa: Allocator, event: []const u8) !Event {
    var scanner = Scanner.initCompleteInput(gpa, event);
    defer scanner.deinit();

    var records: ?[]const Record = null;
    errdefer if (records) |rs| freeRecords(gpa, rs);

    var it = try json.ObjectIterator.init(gpa, &scanner);
    defer it.deinit();
    while (try it.next()) |key| {
        if (mem.eql(u8, "Records", key)) {
            if (records != null) return json.inputError();
            records = try nextRecords(gpa, &scanner);
        } else {
            try scanner.skipValue();
        }
    }

    try json.nextExpect(&scanner, .end_of_document);
    return .{ .records = records orelse return json.inputError() };
}

pub fn encodeResponse(gpa: Allocator, response: Response) ![]const u8 {
    var buffer: std.Io.Writer.Allocating = .init(gpa);
    errdefer buffer.deinit();

    try buffer.writer.writeAll("{\"batchItemFailures\":[");
    for (response.batch_item_failures, 0..) |failure, i| {
        if (i != 0) try buffer.writer.writeByte(',');
        try buffer.writer.writeAll("{\"itemIdentifier\":");
        try std.json.Stringify.encodeJsonString(failure.item_identifier, .{}, &buffer.writer);
        try buffer.writer.writeByte('}');
    }
    try buffer.writer.writeAll("]}");

    return buffer.toOwnedSlice();
}

fn nextRecords(gpa: Allocator, scanner: *Scanner) ![]const Record {
    var list: std.ArrayList(Record) = .empty;
    errdefer {
        for (list.items) |record| record.deinit(gpa);
        list.deinit(gpa);
    }

    var it = try json.ArrayIterator.begin(scanner);
    while (try it.next()) {
        const record = try nextRecord(gpa, scanner);
        errdefer record.deinit(gpa);
        try list.append(gpa, record);
    }

    return list.toOwnedSlice(gpa);
}

fn nextRecord(gpa: Allocator, scanner: *Scanner) !Record {
    var record = RecordBuilder{};
    errdefer record.deinit(gpa);

    var it = try json.ObjectIterator.init(gpa, scanner);
    defer it.deinit();
    while (try it.next()) |key| {
        if (mem.eql(u8, "messageId", key)) {
            record.message_id = try json.nextString(scanner, gpa);
        } else if (mem.eql(u8, "receiptHandle", key)) {
            record.receipt_handle = try json.nextString(scanner, gpa);
        } else if (mem.eql(u8, "body", key)) {
            record.body = try json.nextString(scanner, gpa);
        } else if (mem.eql(u8, "attributes", key)) {
            record.attributes = try json.nextKeyValMap(gpa, scanner);
        } else if (mem.eql(u8, "messageAttributes", key)) {
            record.message_attributes = try nextMessageAttributes(gpa, scanner);
        } else if (mem.eql(u8, "md5OfBody", key)) {
            record.md5_of_body = try json.nextStringOptional(scanner, gpa);
        } else if (mem.eql(u8, "md5OfMessageAttributes", key)) {
            record.md5_of_message_attributes = try json.nextStringOptional(scanner, gpa);
        } else if (mem.eql(u8, "eventSource", key)) {
            record.event_source = try json.nextString(scanner, gpa);
        } else if (mem.eql(u8, "eventSourceARN", key)) {
            record.event_source_arn = try json.nextString(scanner, gpa);
        } else if (mem.eql(u8, "awsRegion", key)) {
            record.aws_region = try json.nextString(scanner, gpa);
        } else {
            try scanner.skipValue();
        }
    }

    return record.toRecord();
}

const RecordBuilder = struct {
    message_id: ?[]const u8 = null,
    receipt_handle: ?[]const u8 = null,
    body: ?[]const u8 = null,
    attributes: []const KeyVal = &.{},
    message_attributes: []const MessageAttribute = &.{},
    md5_of_body: ?[]const u8 = null,
    md5_of_message_attributes: ?[]const u8 = null,
    event_source: ?[]const u8 = null,
    event_source_arn: ?[]const u8 = null,
    aws_region: ?[]const u8 = null,

    fn toRecord(self: RecordBuilder) !Record {
        const event_source = self.event_source orelse return json.inputError();
        if (!mem.eql(u8, event_source, "aws:sqs")) {
            return error.UnexpectedEventSource;
        }

        return .{
            .message_id = self.message_id orelse return json.inputError(),
            .receipt_handle = self.receipt_handle orelse return json.inputError(),
            .body = self.body orelse return json.inputError(),
            .attributes = self.attributes,
            .message_attributes = self.message_attributes,
            .md5_of_body = self.md5_of_body,
            .md5_of_message_attributes = self.md5_of_message_attributes,
            .event_source = event_source,
            .event_source_arn = self.event_source_arn orelse return json.inputError(),
            .aws_region = self.aws_region orelse return json.inputError(),
        };
    }

    fn deinit(self: RecordBuilder, gpa: Allocator) void {
        if (self.message_id) |s| gpa.free(s);
        if (self.receipt_handle) |s| gpa.free(s);
        if (self.body) |s| gpa.free(s);
        json.freeKeyValMap(gpa, self.attributes);
        for (self.message_attributes) |attr| attr.deinit(gpa);
        gpa.free(self.message_attributes);
        if (self.md5_of_body) |s| gpa.free(s);
        if (self.md5_of_message_attributes) |s| gpa.free(s);
        if (self.event_source) |s| gpa.free(s);
        if (self.event_source_arn) |s| gpa.free(s);
        if (self.aws_region) |s| gpa.free(s);
    }
};

fn nextMessageAttributes(gpa: Allocator, scanner: *Scanner) ![]const MessageAttribute {
    var list: std.ArrayList(MessageAttribute) = .empty;
    errdefer {
        for (list.items) |attr| attr.deinit(gpa);
        list.deinit(gpa);
    }

    var it = try json.ObjectIterator.init(gpa, scanner);
    defer it.deinit();
    while (try it.nextAlloc()) |name| {
        const attr = try MessageAttribute.init(gpa, scanner, name);
        errdefer attr.deinit(gpa);
        try list.append(gpa, attr);
    }

    return list.toOwnedSlice(gpa);
}

fn nextStringList(gpa: Allocator, scanner: *Scanner) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |s| gpa.free(s);
        list.deinit(gpa);
    }

    var it = try json.ArrayIterator.begin(scanner);
    while (try it.next()) {
        const item = try json.nextString(scanner, gpa);
        errdefer gpa.free(item);
        try list.append(gpa, item);
    }

    return list.toOwnedSlice(gpa);
}

fn freeRecords(gpa: Allocator, records: []const Record) void {
    for (records) |record| record.deinit(gpa);
    gpa.free(records);
}

fn freeStringList(gpa: Allocator, list: []const []const u8) void {
    for (list) |s| gpa.free(s);
    gpa.free(list);
}

test parseEvent {
    const event = try parseEvent(testing.allocator,
        \\{
        \\  "Records": [
        \\    {
        \\      "messageId": "059f36b4-87a3-44ab-83d2-661975830a7d",
        \\      "receiptHandle": "AQEBwJnKyrHigUMZj6rYigCgxlaS3SLy0a...",
        \\      "body": "Test message.",
        \\      "attributes": {
        \\        "ApproximateReceiveCount": "1",
        \\        "SentTimestamp": "1545082649183",
        \\        "SenderId": "AIDAIENQZJOLO23YVJ4VO",
        \\        "ApproximateFirstReceiveTimestamp": "1545082649185"
        \\      },
        \\      "messageAttributes": {
        \\        "myAttribute": {
        \\          "stringValue": "myValue",
        \\          "stringListValues": [],
        \\          "binaryListValues": [],
        \\          "dataType": "String"
        \\        }
        \\      },
        \\      "md5OfBody": "e4e68fb7bd0e697a0ae8f1bb342846b3",
        \\      "eventSource": "aws:sqs",
        \\      "eventSourceARN": "arn:aws:sqs:us-east-2:123456789012:my-queue",
        \\      "awsRegion": "us-east-2"
        \\    },
        \\    {
        \\      "messageId": "2e1424d4-f796-459a-8184-9c92662be6da",
        \\      "receiptHandle": "AQEBzWwaftRI0KuVm4tP+/7q1rGgNqicHq...",
        \\      "body": "Test message.",
        \\      "attributes": {
        \\        "ApproximateReceiveCount": "1",
        \\        "SentTimestamp": "1545082650636",
        \\        "SenderId": "AIDAIENQZJOLO23YVJ4VO",
        \\        "ApproximateFirstReceiveTimestamp": "1545082650649"
        \\      },
        \\      "messageAttributes": {},
        \\      "md5OfBody": "e4e68fb7bd0e697a0ae8f1bb342846b3",
        \\      "eventSource": "aws:sqs",
        \\      "eventSourceARN": "arn:aws:sqs:us-east-2:123456789012:my-queue",
        \\      "awsRegion": "us-east-2"
        \\    }
        \\  ]
        \\}
    );
    defer event.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), event.records.len);
    try testing.expectEqualStrings("059f36b4-87a3-44ab-83d2-661975830a7d", event.records[0].message_id);
    try testing.expectEqualStrings("Test message.", event.records[0].body);
    try testing.expectEqualStrings("aws:sqs", event.records[0].event_source);
    try testing.expectEqualStrings("arn:aws:sqs:us-east-2:123456789012:my-queue", event.records[0].event_source_arn);
    try testing.expectEqualStrings("us-east-2", event.records[0].aws_region);
    try testing.expectEqual(@as(usize, 4), event.records[0].attributes.len);
    try testing.expectEqualStrings("ApproximateReceiveCount", event.records[0].attributes[0].key);
    try testing.expectEqualStrings("1", event.records[0].attributes[0].value);
    try testing.expectEqual(@as(usize, 1), event.records[0].message_attributes.len);
    try testing.expectEqualStrings("myAttribute", event.records[0].message_attributes[0].name);
    try testing.expectEqualDeep(
        MessageAttributeValue{ .string = "myValue" },
        event.records[0].message_attributes[0].value,
    );
    try testing.expectEqual(null, event.records[0].message_attributes[0].custom_type);
    try testing.expectEqual(@as(usize, 0), event.records[1].message_attributes.len);
}

test "parse FIFO attributes" {
    const event = try parseEvent(testing.allocator,
        \\{
        \\  "Records": [
        \\    {
        \\      "messageId": "11d6ee51-4cc7-4302-9e22-7cd8afdaadf5",
        \\      "receiptHandle": "AQEBBX8nesZEXmkhsmZeyIE8iQAMig7qw...",
        \\      "body": "Test message.",
        \\      "attributes": {
        \\        "ApproximateReceiveCount": "1",
        \\        "SentTimestamp": "1573251510774",
        \\        "SequenceNumber": "18849496460467696128",
        \\        "MessageGroupId": "1",
        \\        "SenderId": "AIDAIO23YVJENQZJOL4VO",
        \\        "MessageDeduplicationId": "1",
        \\        "ApproximateFirstReceiveTimestamp": "1573251510774"
        \\      },
        \\      "messageAttributes": {},
        \\      "md5OfBody": "e4e68fb7bd0e697a0ae8f1bb342846b3",
        \\      "eventSource": "aws:sqs",
        \\      "eventSourceARN": "arn:aws:sqs:us-east-2:123456789012:fifo.fifo",
        \\      "awsRegion": "us-east-2"
        \\    }
        \\  ]
        \\}
    );
    defer event.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), event.records.len);
    try testing.expectEqualStrings("SequenceNumber", event.records[0].attributes[2].key);
    try testing.expectEqualStrings("18849496460467696128", event.records[0].attributes[2].value);
    try testing.expectEqualStrings("MessageGroupId", event.records[0].attributes[3].key);
    try testing.expectEqualStrings("MessageDeduplicationId", event.records[0].attributes[5].key);
}

test "parse message attributes" {
    const event = try parseEvent(testing.allocator,
        \\{
        \\  "Records": [
        \\    {
        \\      "messageId": "id",
        \\      "receiptHandle": "handle",
        \\      "body": "body",
        \\      "attributes": {},
        \\      "messageAttributes": {
        \\        "stringy": {
        \\          "stringValue": "hello \"zig\"",
        \\          "stringListValues": [],
        \\          "binaryListValues": [],
        \\          "dataType": "String"
        \\        },
        \\        "number": {
        \\          "stringValue": "00123.4500",
        \\          "stringListValues": [],
        \\          "binaryListValues": [],
        \\          "dataType": "Number"
        \\        },
        \\        "binary": {
        \\          "binaryValue": "AQID",
        \\          "stringListValues": [],
        \\          "binaryListValues": [],
        \\          "dataType": "Binary"
        \\        },
        \\        "custom": {
        \\          "stringValue": "employee-123",
        \\          "stringListValues": [],
        \\          "binaryListValues": [],
        \\          "dataType": "String.Employee.Id"
        \\        }
        \\      },
        \\      "md5OfBody": "md5",
        \\      "md5OfMessageAttributes": "attr-md5",
        \\      "eventSource": "aws:sqs",
        \\      "eventSourceARN": "arn",
        \\      "awsRegion": "region"
        \\    }
        \\  ]
        \\}
    );
    defer event.deinit(testing.allocator);

    const attrs = event.records[0].message_attributes;
    try testing.expectEqual(@as(usize, 4), attrs.len);
    try testing.expectEqualStrings("stringy", attrs[0].name);
    try testing.expectEqualDeep(
        MessageAttributeValue{ .string = "hello \"zig\"" },
        attrs[0].value,
    );
    try testing.expectEqual(null, attrs[0].custom_type);
    try testing.expectEqualStrings("number", attrs[1].name);
    try testing.expectEqualDeep(
        MessageAttributeValue{ .number = "00123.4500" },
        attrs[1].value,
    );
    try testing.expectEqual(null, attrs[1].custom_type);
    try testing.expectEqualStrings("binary", attrs[2].name);
    try testing.expectEqualDeep(
        MessageAttributeValue{ .binary_base64 = "AQID" },
        attrs[2].value,
    );
    try testing.expectEqual(null, attrs[2].custom_type);
    try testing.expectEqualStrings("custom", attrs[3].name);
    try testing.expectEqualDeep(
        MessageAttributeValue{ .string = "employee-123" },
        attrs[3].value,
    );
    try testing.expectEqualStrings("Employee.Id", attrs[3].custom_type.?);
    try testing.expectEqualStrings("attr-md5", event.records[0].md5_of_message_attributes.?);
}

test "reject invalid message attributes" {
    const invalid_attributes = [_][]const u8{
        // Unknown data type.
        \\{"stringValue":"value","dataType":"Boolean"}
        ,
        // A custom type suffix must contain at least one character.
        \\{"stringValue":"value","dataType":"String."}
        ,
        // String and Number attributes use stringValue.
        \\{"binaryValue":"AQID","dataType":"String"}
        ,
        \\{"binaryValue":"AQID","dataType":"Number"}
        ,
        // Binary attributes use binaryValue.
        \\{"stringValue":"value","dataType":"Binary"}
        ,
        // Every supported type requires its matching value.
        \\{"dataType":"String"}
        ,
        \\{"dataType":"Number"}
        ,
        \\{"dataType":"Binary"}
        ,
        // Reserved list fields must remain empty.
        \\{"stringValue":"value","stringListValues":["reserved"],"dataType":"String"}
        ,
        \\{"binaryValue":"AQID","binaryListValues":["BAU="],"dataType":"Binary"}
        ,
    };

    for (invalid_attributes) |attribute| {
        try expectInvalidMessageAttribute(attribute);
    }
}

fn expectInvalidMessageAttribute(attribute: []const u8) !void {
    const prefix =
        \\{"Records":[{"messageId":"id","receiptHandle":"handle","body":"body",
        \\"attributes":{},"messageAttributes":{"attribute":
    ;
    const suffix =
        \\},"eventSource":"aws:sqs","eventSourceARN":"arn","awsRegion":"region"}]}
    ;
    const event = try mem.concat(testing.allocator, u8, &.{ prefix, attribute, suffix });
    defer testing.allocator.free(event);

    try testing.expectError(error.InvalidInput, parseEvent(testing.allocator, event));
}

test encodeResponse {
    const empty = try encodeResponse(testing.allocator, .{});
    defer testing.allocator.free(empty);
    try testing.expectEqualStrings("{\"batchItemFailures\":[]}", empty);

    const one = try encodeResponse(testing.allocator, .{
        .batch_item_failures = &.{
            .{ .item_identifier = "id1" },
        },
    });
    defer testing.allocator.free(one);
    try testing.expectEqualStrings(
        "{\"batchItemFailures\":[{\"itemIdentifier\":\"id1\"}]}",
        one,
    );

    const many = try encodeResponse(testing.allocator, .{
        .batch_item_failures = &.{
            .{ .item_identifier = "id2" },
            .{ .item_identifier = "id\"4" },
        },
    });
    defer testing.allocator.free(many);
    try testing.expectEqualStrings(
        "{\"batchItemFailures\":[{\"itemIdentifier\":\"id2\"},{\"itemIdentifier\":\"id\\\"4\"}]}",
        many,
    );
}

test "invalid events" {
    try testing.expectError(error.InvalidInput, parseEvent(testing.allocator, "{}"));
    try testing.expectError(error.InvalidInput, parseEvent(testing.allocator, "{\"Records\":null}"));
    try testing.expectError(
        error.InvalidInput,
        parseEvent(testing.allocator,
            \\{
            \\  "Records": [
            \\    {
            \\      "messageId": "id",
            \\      "receiptHandle": "handle",
            \\      "body": "body",
            \\      "attributes": {},
            \\      "messageAttributes": {},
            \\      "eventSource": "aws:sqs",
            \\      "eventSourceARN": "arn"
            \\    }
            \\  ]
            \\}
        ),
    );
    try testing.expectError(
        error.UnexpectedEventSource,
        parseEvent(testing.allocator,
            \\{
            \\  "Records": [
            \\    {
            \\      "messageId": "id",
            \\      "receiptHandle": "handle",
            \\      "body": "body",
            \\      "attributes": {},
            \\      "messageAttributes": {},
            \\      "eventSource": "aws:sns",
            \\      "eventSourceARN": "arn",
            \\      "awsRegion": "region"
            \\    }
            \\  ]
            \\}
        ),
    );
}
