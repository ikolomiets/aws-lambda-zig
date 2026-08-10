//! Processes standard-queue SQS messages and reports partial batch failures.
//!
//! Configure the SQS event source mapping with `ReportBatchItemFailures`.
//! This demo treats a message body equal to "fail" as a failed record.
const std = @import("std");
const mem = std.mem;
const lambda = @import("aws-lambda");

pub fn main(init: std.process.Init) void {
    lambda.handle(init, handler, .{});
}

fn handler(ctx: lambda.Context, payload: []const u8) ![]const u8 {
    const event = try lambda.sqs.parseEvent(ctx.arena, payload);

    var failures: std.ArrayList(lambda.sqs.BatchItemFailure) = .empty;
    for (event.records) |record| {
        if (!mem.eql(u8, record.body, "fail")) continue;

        try failures.append(ctx.arena, .{
            .item_identifier = record.message_id,
        });
    }

    return lambda.sqs.encodeResponse(ctx.arena, .{
        .batch_item_failures = failures.items,
    });
}
