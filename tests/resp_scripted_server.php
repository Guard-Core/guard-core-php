<?php

declare(strict_types=1);

/**
 * Scripted RESP server for the RespConnection error-path tests: it listens
 * on an ephemeral loopback port, prints the port on stdout, accepts one
 * connection, and answers according to $argv[1] so the suite can drive the
 * real stream reader through malformed, truncated, and slow replies.
 *
 * Modes:
 *   int_reply   reply ":0" to every command (a non-array reply for KEYS or
 *               ZRANGEBYSCORE)
 *   null_array  reply "*-1" to every command (a null array reply)
 *   error       reply "-ERR simulated" once, then keep the socket open
 *   null_bulk   reply "$-1" once, then keep the socket open
 *   garbage     reply "@@??" (an unknown RESP type byte)
 *   close_now   close the connection without reading or writing anything
 *   half_bulk   reply "$10\r\nabc" and close (a truncated bulk payload)
 *   hang        read a command then stay silent past the client timeout
 *   rst         accept and immediately close, so a large write dies mid-loop
 */

$mode = $argv[1] ?? 'int_reply';

$server = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "server: {$errstr}\n");
    exit(2);
}
$name = stream_socket_get_name($server, false);
$port = (int) substr($name, strrpos($name, ':') + 1);
fwrite(STDOUT, $port . "\n");
fflush(STDOUT);

$conn = @stream_socket_accept($server, 10);
if ($conn === false) {
    exit(3);
}

switch ($mode) {
    case 'int_reply':
        replyLoop($conn, static function (): string {
            return ":0\r\n";
        });
        break;
    case 'null_array':
        replyLoop($conn, static function (): string {
            return "*-1\r\n";
        });
        break;
    case 'error':
        readOneCommand($conn);
        fwrite($conn, "-ERR simulated\r\n");
        fflush($conn);
        sleep(2);
        break;
    case 'null_bulk':
        readOneCommand($conn);
        fwrite($conn, "\$-1\r\n");
        fflush($conn);
        sleep(2);
        break;
    case 'garbage':
        readOneCommand($conn);
        fwrite($conn, "@@??\r\n");
        fflush($conn);
        sleep(2);
        break;
    case 'close_now':
        fclose($conn);
        break;
    case 'half_bulk':
        readOneCommand($conn);
        fwrite($conn, "\$10\r\nabc");
        fflush($conn);
        fclose($conn);
        break;
    case 'hang':
        readOneCommand($conn);
        sleep(5);
        break;
    case 'rst':
        // Drain nothing, close at once: the client's large write then fails
        // mid-loop on a peer that is gone.
        fclose($conn);
        sleep(2);
        break;
}

fclose($conn);
fclose($server);

function readOneCommand($conn): void
{
    // Consume one RESP command (arrays of bulk strings) without replying.
    $line = fgets($conn);
    if ($line === false) {
        return;
    }
    $count = (int) substr($line, 1);
    for ($i = 0; $i < $count; $i++) {
        $head = fgets($conn);
        if ($head === false) {
            return;
        }
        $len = (int) substr($head, 1);
        if ($len > 0) {
            fread($conn, $len + 2);
        }
    }
}

function replyLoop($conn, callable $reply): void
{
    while (fgets($conn) !== false) {
        fwrite($conn, $reply());
        fflush($conn);
    }
}
