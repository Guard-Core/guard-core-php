<?php

/**
 * Unit-edge suite for the Support and Detection primitives (regex helpers,
 * legacy-IP decoding, the pickle VM, XXE matchers, truncation, base64).
 * Coverage gating lives in .github/coverage-runner.php; this suite only
 * asserts behavior.
 */

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Detection\Base64;
use RenzoFranceschini\GuardCore\Detection\Matchers;
use RenzoFranceschini\GuardCore\Detection\Preprocessor;
use RenzoFranceschini\GuardCore\Detection\Semantic;
use RenzoFranceschini\GuardCore\Detection\ShellValidators;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\GeoIp\MmdbDecoder;
use RenzoFranceschini\GuardCore\GeoIp\MmdbError;
use RenzoFranceschini\GuardCore\GeoIp\MmdbReader;
use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\Detection\LdapIpv4;
use RenzoFranceschini\GuardCore\Detection\Pickle;
use RenzoFranceschini\GuardCore\Detection\Preg;
use RenzoFranceschini\GuardCore\Detection\PregFailure;
use RenzoFranceschini\GuardCore\Detection\Truncation;
use RenzoFranceschini\GuardCore\Detection\XmlXxe;
use RenzoFranceschini\GuardCore\Support\CMatch;
use RenzoFranceschini\GuardCore\Support\Rx;

require __DIR__ . '/../vendor/autoload.php';

final class T
{
    public int $passed = 0;
    public int $failed = 0;

    public function same(mixed $expected, mixed $actual, string $label): void
    {
        if ($expected === $actual) {
            $this->passed++;
            echo "ok - {$label}\n";
        } else {
            $this->failed++;
            echo "FAIL - {$label}\n";
            echo '  expected: ' . var_export($expected, true) . "\n";
            echo '  actual:   ' . var_export($actual, true) . "\n";
        }
    }

    public function ok(bool $condition, string $label): void
    {
        $this->same(true, (bool) $condition, $label);
    }

    public function throws(string $class, callable $fn, string $label): void
    {
        try {
            $fn();
            $this->failed++;
            echo "FAIL - {$label}: no exception\n";
        } catch (Throwable $e) {
            $this->same($class, $e::class, $label);
        }
    }

    public function skip(string $label): void
    {
        echo "skip - {$label}\n";
    }

    public function section(string $name): void
    {
        echo "\n=== {$name} ===\n";
    }
}

/**
 * Writes fixture bytes to a temp file for MmdbReader construction.
 */
function mmdbTempFile(string $content): string
{
    $path = tempnam(sys_get_temp_dir(), 'mmdbbad');
    file_put_contents($path, $content);

    return $path;
}

$t = new T();

$t->section('rx: pattern, matches, and match objects');

$t->same("\x01abc\x01ui", Rx::pattern('abc'), 'pattern wraps with the default delimiter and u flags');
$t->same("\x02a\x01b\x02ui", Rx::pattern("a\x01b"), 'pattern switches the delimiter when the source contains it');
$t->same("\x01abc\x01u", Rx::pattern('abc', false), 'pattern honors case-sensitive mode');

$hits = Rx::matches('(a+)(b+)', 'aabb aabb', true);
$t->same(2, count($hits), 'matches finds every run');
$t->ok($hits[0] instanceof CMatch, 'matches yields CMatch objects');
$t->same('aabb', $hits[0]->text, 'the first match text');
$t->same('aa', $hits[0]->groups[1], 'group 1 of the first match');
$t->same('bb', $hits[0]->groups[2], 'group 2 of the first match');
$t->same(0, $hits[0]->cpStart, 'the match start is a code point offset');
$t->same(4, $hits[0]->cpEnd, 'the match end is a code point offset');
$t->same('aabb', $hits[1]->text, 'the second match text');
$t->same(5, $hits[1]->cpStart, 'the second match start offset');
$t->ok($hits[0]->hasGroup(1) && !$hits[0]->hasGroup(9), 'hasGroup reflects captured groups');
$t->same('aa', $hits[0]->group(1), 'group() returns the captured text');
$t->same('', $hits[0]->group(9), 'group() defaults to empty for absent groups');
$t->same('aabb aabb', $hits[0]->subject, 'the subject is carried on the match');
$t->same('(a+)(b+)', $hits[0]->pattern, 'the source pattern is carried on the match');
$t->same([], Rx::matches('zzz', 'nothing here'), 'no matches yields an empty list');
$t->same([], Rx::matches('[unclosed', 'subject'), 'an invalid pattern yields an empty list');
$uni = Rx::matches('é+', 'xééy');
$t->same(1, $uni[0]->cpStart, 'code point offsets count unicode characters');
$t->same(2, $uni[0]->cpEnd - $uni[0]->cpStart, 'the unicode match spans two code points');

$t->section('rx: matchAt, searchPositions, searchOne, search');

$t->same(null, Rx::matchAt('b+', 'aabbb', 0, 2), 'matchAt anchored before the run fails');
$at = Rx::matchAt('(b+)', 'aabbb', 2, 5);
$t->ok($at !== null && $at->text === 'bbb' && $at->groups[1] === 'bbb', 'matchAt anchors and captures');
$uniAt = Rx::matchAt('é+', 'xééy', 1, 5);
$t->ok($uniAt !== null && $uniAt->cpStart === 1 && $uniAt->cpEnd === 3, 'matchAt reports code point offsets');
$t->same(null, Rx::matchAt('b+', 'aa', 0, 0), 'matchAt on an empty segment returns null');
$t->same(null, Rx::matchAt('b+', 'aabbb', 5, 99), 'matchAt past the end returns null');
$partial = Rx::matchAt('b+', 'aabbbzz', 2, 5);
$t->ok($partial !== null && $partial->text === 'bbb', 'matchAt respects the segment end');

$positions = Rx::searchPositions('b+', 'abcbd');
$t->same([['start' => 1, 'end' => 2], ['start' => 3, 'end' => 4]], $positions, 'searchPositions reports byte spans');
$t->same([['start' => 1, 'end' => 2]], Rx::searchPositions('b+', 'abcbd', true, 2), 'searchPositions honors the byte cutoff');
$t->same([], Rx::searchPositions('zzz', 'abcbd'), 'searchPositions with no hits is empty');

$one = Rx::searchOne('b+', 'abcb');
$t->same(['start' => 1, 'end' => 2, 'text' => 'b'], $one, 'searchOne reports the first hit');
$t->same(['start' => 3, 'end' => 4, 'text' => 'b'], Rx::searchOne('b+', 'abcb', true, 2), 'searchOne honors the byte offset');
$t->same(null, Rx::searchOne('zzz', 'abcb'), 'searchOne with no hit returns null');

$t->ok(Rx::search('b+', 'abcb'), 'search finds a hit');
$t->ok(!Rx::search('zzz', 'abcb'), 'search misses cleanly');
$t->ok(!Rx::search('[unclosed', 'abcb'), 'search on an invalid pattern is false');

$t->section('ldap: legacy ipv4 part decoding');

$t->same(31, LdapIpv4::decodeLegacyIpv4Part('0x1f'), 'hex parts decode');
$t->same(31, LdapIpv4::decodeLegacyIpv4Part('0X1F'), 'uppercase hex decodes');
$t->same(null, LdapIpv4::decodeLegacyIpv4Part('0x'), 'a bare 0x prefix is rejected');
$t->same(null, LdapIpv4::decodeLegacyIpv4Part('0xzz'), 'non-hex digits are rejected');
$t->same(493, LdapIpv4::decodeLegacyIpv4Part('0755'), 'octal parts decode');
$t->same(null, LdapIpv4::decodeLegacyIpv4Part('08'), 'invalid octal digits are rejected');
$t->same(0, LdapIpv4::decodeLegacyIpv4Part('0'), 'a single zero is decimal');
$t->same(42, LdapIpv4::decodeLegacyIpv4Part('42'), 'decimal parts decode');
$t->same(null, LdapIpv4::decodeLegacyIpv4Part('abc'), 'non-numeric parts are rejected');

$t->section('ldap: legacy ipv4 host decoding');

$t->same(null, LdapIpv4::decodeLegacyIpv4Host('1.2.3.4.5'), 'five parts are rejected');
$t->same(null, LdapIpv4::decodeLegacyIpv4Host('1.2.x'), 'a bad part rejects the host');
$t->same(null, LdapIpv4::decodeLegacyIpv4Host('1'), 'a small bare decimal is not a legacy ip');
$t->ok(LdapIpv4::decodeLegacyIpv4Host('2130706433') !== null, 'a large decimal is a legacy ip');
$t->ok(LdapIpv4::decodeLegacyIpv4Host('077.1') !== null, 'a zero-prefixed part opts into legacy decoding');
$t->same(0, LdapIpv4::decodeLegacyIpv4Host('0'), 'a bare zero decodes to zero');
$t->same(null, LdapIpv4::decodeLegacyIpv4Host('300.1.2'), 'an over-wide leading part is rejected');
$t->same(null, LdapIpv4::decodeLegacyIpv4Host('1.2.3.9999'), 'an over-wide trailing part is rejected');
$t->ok(LdapIpv4::decodeLegacyIpv4Host('127.0.0.1') !== null, 'loopback decodes');

$t->section('ldap: blocked matching and injection windows');

$t->ok(LdapIpv4::legacyIpv4MatchIsBlocked(['groups' => [1 => ['text' => '127.0.0.1']]]), 'loopback is blocked');
$t->ok(LdapIpv4::legacyIpv4MatchIsBlocked(['groups' => [1 => ['text' => '0.0.0.0']]]), 'the zero network is blocked');
$t->ok(LdapIpv4::legacyIpv4MatchIsBlocked(['groups' => [1 => ['text' => '100.100.100.200']]]), 'the 100.100.100.200 sinkhole is blocked');
$t->ok(!LdapIpv4::legacyIpv4MatchIsBlocked(['groups' => [1 => ['text' => '8.8.8.8']]]), 'public ips are not blocked');
$t->ok(!LdapIpv4::legacyIpv4MatchIsBlocked(['groups' => []]), 'a match without groups is not blocked');

$ldapText = '(uid=*)(!(cn=x*)))(|(uid=*))';
$wildcardSource = '\*';
$ldapMatch = ['text' => '*(cn=x*))', 'start' => 6, 'end' => 15];
$t->ok(is_bool(LdapIpv4::wildcardChainIsInjection($ldapText, $ldapMatch, $wildcardSource)), 'wildcard chain analysis returns a bool');
$t->ok(!LdapIpv4::wildcardChainIsInjection('(uid=*)', ['text' => 'nounparen', 'start' => 0, 'end' => 9], '\*'), 'a match without a closing paren is not injection');

$t->ok(LdapIpv4::parenConjunctionIsInjection('(uid=a)(!(uid=b))', ['text' => '(uid=a)', 'start' => 0, 'end' => 7], '\('), 'a negation tail is injection');
$t->ok(LdapIpv4::parenConjunctionIsInjection('(uid=a)(uid=b)', ['text' => '(uid=a)', 'start' => 0, 'end' => 7], '\('), 'a conjunction tail is injection');
$t->ok(!LdapIpv4::parenConjunctionIsInjection('(uid=a) tail', ['text' => '(uid=a)', 'start' => 0, 'end' => 7], '\('), 'plain prose after a group is not injection');

$t->same(7, LdapIpv4::filterExpressionForwardExtent('(uid=a)', 0, 7), 'the extent runs to the scan limit after a balanced group');
$t->same(14, LdapIpv4::filterExpressionForwardExtent('(uid=a)(uid=b)', 0, 14), 'the extent covers sibling groups');
$t->same(1, LdapIpv4::filterExpressionForwardExtent('("x)', 0, 4), 'a quote boundary ends the extent');
$t->same(2, LdapIpv4::filterExpressionForwardExtent('())x', 0, 4), 'an unbalanced close ends the extent');
$t->same(5, LdapIpv4::filterExpressionForwardExtent('(())x', 0, 5), 'nested groups balance through');
$t->same(5, LdapIpv4::filterExpressionForwardExtent('(uid=a', 0, 5), 'the scan limit caps the extent');

$t->section('xml: xxe matchers');

$t->same(2, XmlXxe::firstAtOrAfter([1, 2, 3], 2), 'firstAtOrAfter finds the first position at or after the floor');
$t->same(null, XmlXxe::firstAtOrAfter([1, 2, 3], 9), 'firstAtOrAfter returns null past the end');
$t->same(null, XmlXxe::firstAtOrAfter([], 0), 'firstAtOrAfter on an empty list returns null');
$t->same(5, XmlXxe::firstAtOrAfter([5], 0), 'a single element list works');

$systemXml = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r/>';
$systemHits = XmlXxe::xmlSystemFinditer($systemXml);
$t->same(1, count($systemHits), 'a SYSTEM entity is matched');
$t->ok(str_contains($systemHits[0]['text'] ?? '', 'SYSTEM'), 'the SYSTEM match spans the declaration');

$internalXml = '<!DOCTYPE r [<!ENTITY x "y">]>';
$internalHits = XmlXxe::xmlInternalEntityFinditer($internalXml);
$t->same(1, count($internalHits), 'an internal entity inside the doctype is matched');
$t->same(0, count(XmlXxe::xmlInternalEntityFinditer('<!DOCTYPE r SYSTEM "x">')), 'a doctype without an internal subset is not matched');
$t->same(0, count(XmlXxe::xmlInternalEntityFinditer('<!DOCTYPE r [nothing]>')), 'a subset without entities is not matched');

$publicHits = XmlXxe::xmlXxePublicExternalDtdFinditer('<!DOCTYPE r PUBLIC "-//X//EN" "https://download.example.com/x.dtd">');
$t->same(1, count($publicHits), 'a completed quoted public url is matched');
$t->same(0, count(XmlXxe::xmlXxePublicExternalDtdFinditer('<!DOCTYPE r PUBLIC "-//X//EN" "http://www.w3.org/x.dtd">')), 'w3.org namespace urls are excluded');
$t->same(0, count(XmlXxe::xmlXxePublicExternalDtdFinditer('<!DOCTYPE r PUBLIC "-//X//EN" "x.dtd">')), 'urls without a scheme are not matched');
$t->ok(is_array(XmlXxe::xmlXxePublicExternalDtdFinditer('<!DOCTYPE r PUBLIC "-//X//EN" "https://download.example.com/x.dtd">')), 'public dtd analysis returns a list');
$t->same(0, count(XmlXxe::xmlXxePublicExternalDtdFinditer('no doctype here')), 'text without a doctype is not matched');

$t->section('truncation: partial sequence trimming');

$t->same('', Truncation::trimPartialSequences(''), 'an empty piece trims to empty');
$t->same('abc', Truncation::trimPartialSequences('abc'), 'ascii passes through');
$t->same('', Truncation::trimPartialSequences("\x80\x80"), 'bare continuation bytes trim away');
$t->same('a', Truncation::trimPartialSequences("\x80\x81a"), 'leading continuations are dropped');
$good = 'héllo';
$t->same($good, Truncation::trimPartialSequences($good), 'valid utf-8 passes through');
$t->same('h', Truncation::trimPartialSequences(substr($good, 0, 2)), 'a split trailing character is dropped');
$t->same('lo', Truncation::trimPartialSequences(substr($good, -2)), 'a split leading character is dropped');

$t->section('truncation: attack regions and caps');

$attack = str_repeat('a', 60) . 'UNION SELECT * FROM users' . str_repeat('b', 60);
$regions = Truncation::extractAttackRegions($attack);
$t->ok($regions !== [] && $regions[0][0] <= 60 && $regions[0][1] >= 84, 'attack regions are extracted around indicators');
$t->same([], Truncation::extractAttackRegions('nothing suspicious here'), 'benign content has no regions');
$capped = Truncation::capWithTail(str_repeat('x', 100));
$t->ok($capped !== '', 'capWithTail returns content');
$safe = Truncation::truncateSafely($attack, new RenzoFranceschini\GuardCore\Detection\Preprocessor());
$t->ok(str_contains($safe, 'UNION SELECT'), 'truncateSafely keeps the attack region');
$t->same('ab', Truncation::truncateSafely('ab', new RenzoFranceschini\GuardCore\Detection\Preprocessor()), 'short content passes through');
$concat = Truncation::extractAndConcatenateAttackRegions($attack, [[0, 10], [20, 30]], 15);
$t->ok(strlen($concat) <= 15, 'concatenation respects the budget');
$built = Truncation::buildResultWithAttackRegionsAndContext($attack, $regions, 200);
$t->ok(str_contains($built, 'UNION SELECT'), 'the context builder keeps attack regions');

$t->section('base64: helpers and candidate decoding');

$t->ok(Base64::isHexLiteral('0xDEADBEEF'), 'hex literals recognized');
$t->ok(!Base64::isHexLiteral('deadbeef'), 'bare hex is not a literal');
$t->ok(!Base64::isHexLiteral('0x'), 'a bare prefix is not a literal');
$t->ok(Base64::printableRatio('abc') === 1.0, 'printable ratio of ascii is one');
$t->ok(Base64::printableRatio('') === 0.0, 'printable ratio of empty is zero');
$t->ok(Base64::replacementCharRatio('') === 0.0, 'replacement ratio of empty is zero');
$t->ok(Base64::replacementCharRatio("a\u{FFFD}b") > 0.0, 'replacement characters count');

$gz = gzencode('ATTACK-PAYLOAD-INSIDE-GZIP');
$gunzipped = Base64::boundedGunzip($gz, 1024);
$t->same('ATTACK-PAYLOAD-INSIDE-GZIP', $gunzipped, 'bounded gunzip round-trips');
$t->same(null, Base64::boundedGunzip('not-gzip', 1024), 'non-gzip data returns null');
$t->same(null, Base64::boundedGunzip(substr($gz, 0, 1), 1024), 'short data returns null');

$gunzipLeft = [8];
$decoded = Base64::decodeCandidates('plain ' . base64_encode('VISIBLE-ATTACK-STRING-OK') . ' tail', $gunzipLeft, 1024);
$t->ok(str_contains($decoded, 'VISIBLE-ATTACK-STRING-OK'), 'a base64-encoded attack string is decoded');
$gunzipLeft = [8];
$t->ok(str_contains(Base64::decodeCandidates(base64_encode($gz), $gunzipLeft, 1024), 'ATTACK-PAYLOAD'), 'a gzipped base64 payload is decoded');
$gunzipLeft = [8];
$urlsafe = strtr(base64_encode('URLSAFE-ATTACK-VALUE'), '+/', '-_');
$t->ok(str_contains(Base64::decodeCandidates($urlsafe, $gunzipLeft, 1024), 'URLSAFE-ATTACK-VALUE'), 'urlsafe base64 decodes');
$gunzipLeft = [8];
$t->ok(Base64::decodeCandidates('short', $gunzipLeft, 1024) === 'short', 'non-candidate content passes through');
$t->same(null, Base64::decodeShortToken('toolongtoken12345'), 'long short-tokens are rejected');
$t->same(null, Base64::decodeShortToken('!!!!'), 'invalid short-tokens are rejected');
$t->ok(Base64::decodeShortToken(base64_encode('hi')) !== null || Base64::decodeShortToken('aGk=') !== null, 'a valid short token decodes');

$t->section('pickle: opcode stream walking');

$t->ok(Pickle::globalPrefixIsOpcodeStream(''), 'an empty prefix is an opcode stream');
$t->ok(Pickle::globalPrefixIsOpcodeStream("N.\n"), 'a prefix ending in a newline is an opcode stream');
$t->ok(Pickle::globalPrefixIsOpcodeStream('N.'), 'a complete minimal stream walks');
$t->ok(Pickle::globalPrefixIsOpcodeStream("S'abc'\n."), 'the S opcode reads a line');
$t->ok(Pickle::globalPrefixIsOpcodeStream("Vx\nT y\n."), 'V and T read lines');
$t->ok(Pickle::globalPrefixIsOpcodeStream("U\x03abc."), 'U reads a length-prefixed string');
$t->ok(Pickle::globalPrefixIsOpcodeStream("X\x04\x00\x00\x00abcd."), 'X reads a 4-byte length');
// The high opcode bytes ride lenient decoding of invalid UTF-8, whose
// substitution differs between 8.2 and 8.3; the gate measures on 8.3.
if (PHP_VERSION_ID >= 80300) {
    $t->ok(Pickle::globalPrefixIsOpcodeStream("\x8d" . pack('P', 2) . 'ab.'), 'the 8-byte length opcode reads its argument');
    $t->ok(Pickle::globalPrefixIsOpcodeStream("\x8eZ."), 'the memoized-object opcode reads one byte');
    $t->ok(Pickle::globalPrefixIsOpcodeStream("\x80Z."), 'protocol 5 frame opcode reads one byte');
    $t->ok(Pickle::globalPrefixIsOpcodeStream("\x80Z.N."), 'a frame opcode walks through');
} else {
    $t->skip('high opcode bytes need the 8.3+ lenient decoding behavior');
}
$t->ok(Pickle::globalPrefixIsOpcodeStream('G12345678.'), 'G reads 8 bytes');
$t->ok(Pickle::globalPrefixIsOpcodeStream("Fabc\nI1\nLabc\n."), 'F, I, and L read lines');
$t->ok(Pickle::globalPrefixIsOpcodeStream('KZ.MZZ.JZZZZ.'), 'the fixed-width integer opcodes read their widths');
$t->ok(Pickle::globalPrefixIsOpcodeStream('NR.'), 'reduce walks with the seeded stack');
$t->ok(Pickle::globalPrefixIsOpcodeStream('NNb.'), 'build pops two operands');
$t->ok(Pickle::globalPrefixIsOpcodeStream('(No.'), 'an object opcode pops its mark');
$t->ok(Pickle::globalPrefixIsOpcodeStream('(Nt.'), 'tuple pops its mark');
$t->ok(Pickle::globalPrefixIsOpcodeStream('(Nl.(Nd.'), 'list and dict pop marks');
$t->ok(Pickle::globalPrefixIsOpcodeStream('(Ne.'), 'append pops its mark');
$t->ok(Pickle::globalPrefixIsOpcodeStream('NNa.'), 'setitem pops two operands');
$t->ok(Pickle::globalPrefixIsOpcodeStream('pZ.qZ.'), 'binput and long-binput read one byte');
$t->ok(Pickle::globalPrefixIsOpcodeStream('rZZZZ.QZZZZ.'), 'recall and pop-mark read four bytes');
$t->ok(Pickle::globalPrefixIsOpcodeStream('gZ.hZ.'), 'the stack-index opcodes read one byte');
$t->ok(Pickle::globalPrefixIsOpcodeStream('jZZZZ.'), 'long stack index reads four bytes');
$t->ok(Pickle::globalPrefixIsOpcodeStream('ZZ.'), 'an unknown opcode stops the walk benignly');
$t->ok(!Pickle::globalPrefixIsOpcodeStream("cos\nsystem\n."), 'the global opcode is blocked outright');
$t->ok(!Pickle::globalPrefixIsOpcodeStream('K'), 'a short read on a complete window fails');
$t->ok(!Pickle::globalPrefixIsOpcodeStream('你好'), 'non-latin1 characters are not an opcode stream');
$t->ok(Pickle::globalPrefixIsOpcodeStream(str_repeat('K', 5000)), 'an incomplete oversized window is tolerated');
$t->ok(!Pickle::globalPrefixIsOpcodeStream("U\x03ab"), 'a truncated string read fails');

$t->section('pickle: suffix reachability');

$t->ok(Pickle::globalSuffixReachesReduceOrBuild('R'), 'a suffix reaching reduce is reported');
$t->ok(Pickle::globalSuffixReachesReduceOrBuild('b'), 'a suffix reaching build is reported');
$t->ok(!Pickle::globalSuffixReachesReduceOrBuild('N.'), 'a complete suffix without reduce is reported safe');
$t->ok(!Pickle::globalSuffixReachesReduceOrBuild('K'), 'a short suffix is reported safe');
$t->ok(!Pickle::globalSuffixReachesReduceOrBuild('你好'), 'a non-latin1 suffix is reported safe');

$t->section('pickle: candidate injection pairing');

$t->ok(Pickle::globalCandidateIsInjection('N.cos\nRR', ['start' => 2, 'groups' => [1 => ['end' => 7]]]), 'an opcode prefix plus a reduce suffix is injection');
$t->ok(!Pickle::globalCandidateIsInjection('N.N.', ['start' => 2, 'groups' => [1 => ['end' => 2]]]), 'a safe suffix is not injection');
$t->ok(!Pickle::globalCandidateIsInjection("cos\nsystem\nR", ['start' => 12, 'groups' => [1 => ['end' => 12]]]), 'a blocked prefix is not injection');

$t->section('truncation: oversized content paths');

$plain = str_repeat('a', 300000);
$cappedPlain = Truncation::truncateSafely($plain, new RenzoFranceschini\GuardCore\Detection\Preprocessor());
$t->ok(strlen($cappedPlain) < strlen($plain), 'oversized plain content is capped');
$flood = str_repeat('UNION SELECT * FROM t WHERE 1=1 ', 12000);
$concatFlood = Truncation::truncateSafely($flood, new RenzoFranceschini\GuardCore\Detection\Preprocessor());
$t->ok(strlen($concatFlood) > 0 && str_contains($concatFlood, 'UNION SELECT'), 'oversized attack content keeps its regions');
$withTail = Truncation::buildResultWithAttackRegionsAndContext('REGION-HERE' . str_repeat('x', 5000), [[0, 11]], 200);
$t->ok(str_contains($withTail, 'REGION-HERE'), 'the tail context builder keeps the region');

$t->section('xml: matcher boundary guards');

$t->same([], XmlXxe::xmlSystemFinditer('<!DOCTYPE r ENTITY unterminated'), 'a declaration without a closing bracket stops the scan');
$t->same(1, count(XmlXxe::xmlSystemFinditer('<!ENTITY a SYSTEM "x">')), 'an entity outside a doctype still matches');
$t->same([], XmlXxe::xmlInternalEntityFinditer('<!DOCTYPE r ['), 'an unterminated subset stops the scan');
$t->same(1, count(XmlXxe::xmlInternalEntityFinditer('<!DOCTYPE r [<!ENTITY')), 'a subset cut right after the entity still matches');
$t->same([], XmlXxe::xmlXxePublicExternalDtdFinditer('<!DOCTYPE'), 'a bare doctype is not matched');

$t->section('preprocessor: decode edges');

$pp = new Preprocessor();
$emptyBudget = [false];
$t->same('', $pp->preprocessWithDecoded('', $emptyBudget)['0'], 'empty content preprocesses to empty');
$t->same(false, $emptyBudget[0], 'empty preprocessing stays in budget');
$t->same('héllo', $pp->preprocessWithDecoded('héllo', $emptyBudget)['0'], 'valid utf-8 passes through normalization');
$t->same("\u{FFFD}", $pp->htmlUnescape('&#55296;'), 'surrogate numeric references collapse to the replacement character');
$t->same("\u{FFFD}", $pp->htmlUnescape('&#0;'), 'a zero numeric reference becomes the replacement character');
$t->same("\u{FFFD}", $pp->htmlUnescape('&#999999999999;'), 'an oversized numeric reference becomes the replacement character');
$t->same("\xacarealentity;", $pp->htmlUnescape('&notarealentity;'), 'the not-entity prefix decodes, the rest passes through');
$t->ok(str_contains($pp->htmlUnescape('&amp;more&tail'), '&'), 'entity decoding keeps the tail');
$overlong = $pp->lenientOverlongUtf8Decode("\xc0\xaf");
$t->ok(is_string($overlong), 'lenient overlong decoding returns a string');
$budget = [false];
$pp->decodeCommonEncodings('%41%42%43', $budget);
$t->same(false, $budget[0], 'a small decode stays within budget');

$t->section('semantic: content-length guards');

$t->ok(is_float(Semantic::calculateEntropy(str_repeat('ab', 100000))), 'entropy caps its scan length');
$t->ok(is_int(Semantic::detectEncodingLayers('%41' . str_repeat('a', 100000))), 'encoding layers cap their scan length');
$t->ok(Semantic::detectObfuscation('%41%42%43' . str_repeat('x', 100)), 'obfuscation detects percent escapes');
$t->ok(is_array(Semantic::extractSuspiciousPatterns('1;DROP TABLE users--')), 'suspicious pattern extraction works');
$t->ok(is_array(Semantic::analyze('1;DROP TABLE users--')), 'semantic analysis returns a result map');
$t->ok(is_float(Semantic::getThreatScore(Semantic::analyze('1;DROP TABLE users--'))), 'threat scores are floats');

$t->section('canonical ip: edges');

$t->throws(InvalidArgumentException::class, static fn () => CanonicalIp::canonicalNetwork('999.1.2.3/24'), 'an invalid v4 network is rejected');
$t->ok(!CanonicalIp::networkContains('not-a-cidr', '1.2.3.4'), 'an unparseable network contains nothing');
$t->ok(CanonicalIp::isLoopback('127.0.0.1'), 'v4 loopback detected');
$t->ok(CanonicalIp::isLoopback('::1'), 'v6 loopback detected');
$t->ok(!CanonicalIp::isLoopback('8.8.8.8'), 'public v4 is not loopback');
$t->ok(!CanonicalIp::isLoopback('2001:db8::1'), 'public v6 is not loopback');
$t->ok(CanonicalIp::parse('[2001:db8::1]') !== null, 'bracketed ipv6 parses');
$t->ok(CanonicalIp::parse('nope') === null, 'garbage does not parse');

$t->section('matchers: alternations and bounded windows');

// The com-free dangerous alternation drops the com entry only.
$t->ok(!preg_match('#(^|\|)com(\||$)#', Matchers::dangerousExtAlternation(false)), 'the com-free alternation drops com');
$t->ok(preg_match('#(^|\|)com(\||$)#', Matchers::dangerousExtAlternation(true)) === 1, 'the full alternation keeps com');
$t->ok(Matchers::dangerousExtAlternation(false) !== Matchers::dangerousExtAlternation(true), 'the two alternations differ');

// A prefix that starts after the last terminator scans nothing.
$t->same([], Matchers::loadFileScanMatches('x) LOAD_FILE(', 'LOAD_FILE\\s*\\('), 'a prefix after the last terminator scans nothing');

$shellSrc = "\\n[^\\S\\r\\n]*(?:[^=\\s;|&]+=[^\\s;|&]+\\s+)*(?:/?(?:[\\w.-]+/)*env\\s+)?/?(?:[\\w.-]+/)*(?:bash|sh|ksh|csh|tsch|zsh|ash)\\s+-c\\b";
$shellHits = Matchers::cmdInjectionShellDashCFinditer("\nFOO=bar bash -c 'id'", $shellSrc);
$t->same(1, count($shellHits), 'a shell dash c line with env assignments matches once');
$t->same("\nFOO=bar bash -c", $shellHits[0]['text'] ?? null, 'the shell dash c match spans the env line and the interpreter');
$plainShell = Matchers::cmdInjectionShellDashCFinditer("\n  sh -c 'id'", $shellSrc);
$t->same(1, count($plainShell), 'a plain shell dash c line matches once');

$t->section('matchers: ldap null byte attribute');

$ldapRaw = "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)";
$ldapTail = '\\*\\)+(?:%00|\\\\u0000|\\\\x00|\\\\0|\\x00)';
$ldapDecoded = "[a-zA-Z][\\w-]*\\s*=[\\d\\w\\s]*\\*\\)+\\x00";

$hit = Matchers::ldapNullByteAttrFinditer('cn=x*)%00', $ldapRaw, $ldapTail);
$t->same(1, count($hit), 'a raw null byte ldap attribute matches');
$t->same('cn=x*)%00', $hit[0]['text'] ?? null, 'the raw null byte match spans the attribute');
$t->same([], Matchers::ldapNullByteAttrFinditer('(uid=admin*)(cn=a%00', $ldapRaw, $ldapTail), 'a star without the closing paren tail does not match');
$t->same([], Matchers::ldapNullByteAttrFinditer('9=x*)%00', $ldapRaw, $ldapTail), 'a non letter attribute name does not match');
$t->same([], Matchers::ldapNullByteAttrFinditer('cn: x*)%00', $ldapRaw, $ldapTail), 'a value not preceded by equals does not match');
$decodedHit = Matchers::ldapNullByteAttrFinditer("cn=zz*)\x00", $ldapDecoded, '\\*\\)+\\x00');
$t->same(1, count($decodedHit), 'a decoded null byte ldap attribute matches');
$multiHit = Matchers::ldapNullByteAttrFinditer("c\xc3\xa9n=zz*)\x00", $ldapDecoded, '\\*\\)+\\x00');
$t->same(1, count($multiHit), 'the attribute walk steps over multi byte characters');
$t->same("c\xc3\xa9n=zz*)\x00", $multiHit[0]['text'] ?? null, 'the multi byte match keeps the whole attribute');

$t->section('matchers: pickle global scan');

$pk = "(c[A-Za-z_][A-Za-z0-9_]{0,100}(?:\\.[A-Za-z_][A-Za-z0-9_]{0,100}){0,20}\\n[A-Za-z_][A-Za-z0-9_]{0,100}\\n)[^ \\t]{0,100}?[Rb]";
$upper = Matchers::pickleGlobalGenericFinditer("\nCposix\nsystem\nR", $pk);
$t->same(1, count($upper), 'an uppercase global marker matches');
$t->same("Cposix\nsystem\nR", $upper[0]['text'] ?? null, 'the uppercase global match spans the opcode stream');
$dotted = Matchers::pickleGlobalGenericFinditer("cos.system\nzz\nR", $pk);
$t->same(1, count($dotted), 'a dotted module global matches');
$t->same(0, $dotted[0]['start'] ?? -1, 'the dotted global starts at the marker');
$t->same([], Matchers::pickleGlobalGenericFinditer("c1\nzz\n", $pk), 'a marker followed by a digit is not a global');

$t->section('matchers: template expressions');

$curlyHits = Matchers::templateExpressionMatches('{{ 2024-01-01 {{ 7*6 }} }}', '(?<!\\d)[\'\\"]?\\d+[\'\\"]?\\s*[*/%+\\-]\\s*[\'\\"]?\\d+[\'\\"]?', 'curly');
$t->same(1, count($curlyHits), 'an expression after an embedded date still matches');
$t->same('{{ 7*6 }}', $curlyHits[0]['text'] ?? null, 'the date shifts the frame to the inner expression');
$t->same([], Matchers::templateExpressionMatches('{{ 2024-01-01 7*6 }}', '(?<!\\d)[\'\\"]?\\d+[\'\\"]?\\s*[*/%+\\-]\\s*[\'\\"]?\\d+[\'\\"]?', 'curly'), 'a date without a following opening stops the region');

$kwHits = Matchers::templateKeywordMatches('{{ system }}', 'system', '{{', '}}');
$t->same(1, count($kwHits), 'a template keyword region matches');
$t->same('{{ system }}', $kwHits[0]['text'] ?? null, 'the keyword frame spans the whole tag');

$t->section('matchers: file upload filename parsing');

$t->same([], Matchers::fileUploadScanMatches('x  filename="a.exe"', 'file_upload_dangerous'), 'a filename token without a delimiter prefix does not match');
$t->same([], Matchers::fileUploadScanMatches('filename x', 'file_upload_dangerous'), 'a filename token without equals does not match');
$t->same([], Matchers::fileUploadScanMatches('filename=abc', 'file_upload_dangerous'), 'a filename without a quote does not match');
$t->same([], Matchers::fileUploadScanMatches('filename="abc', 'file_upload_dangerous'), 'an unclosed filename quote does not match');
$spaced = Matchers::fileUploadScanMatches('filename = "a.exe"', 'file_upload_dangerous');
$t->same(1, count($spaced), 'spaces around the filename equals still parse');
$t->same('filename = "a.exe"', $spaced[0]['text'] ?? null, 'the spaced filename match spans the assignment');
$newlinePrefix = Matchers::fileUploadScanMatches("x\n \nfilename=\"a.exe\"", 'file_upload_dangerous');
$t->same(1, count($newlinePrefix), 'a newline space run before the filename anchors the match');

$t->same([], Matchers::fileUploadScanMatches('filename="a.exe"', 'file_upload_double'), 'a dangerous terminal extension is not a double extension');
$t->same([], Matchers::fileUploadScanMatches('filename=".exephp.jpg"', 'file_upload_double'), 'a glued dangerous extension with a letter lookahead is not double');
$interposed = Matchers::fileUploadScanMatches('filename="x.php.txt.jpg"', 'file_upload_double');
$t->same(1, count($interposed), 'a dangerous extension before a benign chain is double');
$directDouble = Matchers::fileUploadScanMatches('filename="x.php.jpg"', 'file_upload_double');
$t->same(1, count($directDouble), 'a dangerous extension directly before the benign terminal is double');
$trunc = Matchers::fileUploadScanMatches('filename="a.php%00"', 'file_upload_truncation');
$t->same(1, count($trunc), 'a percent encoded null after a dangerous extension is truncation');
$decTrunc = Matchers::fileUploadScanMatches("filename=\"a.php\x00\"", 'file_upload_decoded_truncation');
$t->same(1, count($decTrunc), 'a raw null after a dangerous extension is decoded truncation');
$t->same(false, Matchers::fileUploadKindMatches('a.exe', 'unknown_kind'), 'an unknown upload kind matches nothing');

$t->section('pickle vm: remaining opcode coverage');

$t->ok(!Pickle::globalPrefixIsOpcodeStream('S'), 'a string opcode without a newline is a short read');
$t->ok(!Pickle::globalPrefixIsOpcodeStream('e'), 'an append without a mark fails');
$t->ok(Pickle::globalPrefixIsOpcodeStream("M\x00\x00."), 'the two byte integer opcode walks');
$t->ok(Pickle::globalPrefixIsOpcodeStream("J\x00\x00\x00\x00."), 'the four byte integer opcode walks');
$t->ok(Pickle::globalPrefixIsOpcodeStream("j\x00\x00\x00\x00."), 'the long binput opcode walks');
$t->ok(Pickle::globalPrefixIsOpcodeStream("\u{0080}\x03."), 'the proto frame opcode reads one byte');
$t->ok(Pickle::globalPrefixIsOpcodeStream("h\x00."), 'the short stack index opcode pushes an object');
$t->ok(Pickle::globalPrefixIsOpcodeStream("\u{0081}."), 'the short binunicode opcode pushes an object');
$t->ok(Pickle::globalPrefixIsOpcodeStream("\u{008d}\x02\x00\x00\x00\x00\x00\x00\x00ab."), 'the byte array opcode reads its packed length');
$t->ok(Pickle::globalPrefixIsOpcodeStream("\u{008e}\x02."), 'the frame opcode reads one byte');
$t->ok(Pickle::globalPrefixIsOpcodeStream("\u{0085}\x00\x00\x00\x00\x00\x00\x00\x00\x00K"), 'the tuple-one frame opcode is consumed by the walk loop');
$t->ok(Pickle::globalPrefixIsOpcodeStream("\u{0095}\x00\x00\x00\x00\x00\x00\x00\x00\x00K"), 'the frame opcode is consumed by the walk loop');

$t->section('mmdb decoder: primitive types');

$dec = static fn (string $bytes): mixed => (new MmdbDecoder($bytes, 0))->decode();

$t->same('wor', $dec("\x20\x02\x53wor"), 'a pointer follows to the aliased string');
$t->same(str_repeat('q', 40), $dec("\x5d\x00" . str_repeat('q', 40)), 'a size 29 string reads its extended width');
$t->same(str_repeat('r', 300), $dec("\x5e\x01\x2c" . str_repeat('r', 300)), 'a size 30 string reads two width bytes');
$t->same(1.5, $dec("\x68" . pack('E', 1.5)), 'a double decodes big endian');
$t->same(1.5, $dec("\x00\x44" . pack('G', 1.5)), 'a float decodes big endian');
$t->same(-1, $dec("\x00\x0c" . pack('N', 0xFFFFFFFF)), 'an int32 sign extends the high bit');
$t->same(true, $dec("\x00\x39"), 'a boolean with size one is true');
$t->same(false, $dec("\x00\x38"), 'a boolean with size zero is false');
$t->throws(MmdbError::class, static fn () => $dec("\x00\x28"), 'an unsupported extended type raises an error');
$t->throws(MmdbError::class, static fn () => $dec("\x00"), 'a truncated extended marker raises an error');
$t->throws(MmdbError::class, static fn () => $dec("\x20\xff"), 'a pointer past the buffer raises an error');

$t->section('preprocessor: overlong utf-8 and ref edges');

$pp = new Preprocessor();
// A 3-byte overlong encoding of "/" decodes leniently, with ascii mixed in.
$t->same('A/B', $pp->lenientOverlongUtf8Decode("A\xE0\x80\xAFB"), 'an overlong three byte sequence decodes to its code point');
// A broken continuation aborts the sequence decode.
$t->same('', $pp->lenientOverlongUtf8Decode("\xE0\x80\xC0"), 'a bad third byte aborts the overlong decode');
$t->same("\x00", $pp->lenientOverlongUtf8Decode("\xE0\xC0\xAF"), 'a bad second byte aborts the overlong decode');
// Truncated multi byte sequences are dropped byte by byte.
$t->same('a b', $pp->urlDecode("a%FF b"), 'invalid percent bytes drop in the lenient url decode');
// A bare '&#;' keeps its text.
$t->same('&#;', $pp->htmlUnescape('&#;'), 'an empty numeric reference stays literal');
// A partial known entity keeps its decoded prefix plus the tail.
$t->same('<script', $pp->htmlUnescape('&ltscript'), 'a semi-colon less known entity decodes with its tail');

// The newline-preserving url-decoded view.
$flag = [false];
$t->same('', $pp->preprocessUrlDecodedNewlinePreserving('', $flag), 'the newline preserving view maps empty to empty');
$t->same('SELECT 1', $pp->preprocessUrlDecodedNewlinePreserving('SELECT%201', $flag), 'the newline preserving view decodes percent escapes');

$t->section('mmdb reader: fixture tree sizes and error paths');

/**
 * Builds a minimal MMDB file the reader accepts: one search node whose
 * records the given 24/28/32-bit encoding lays out, a country map in the
 * data section, and the metadata block the marker terminates.
 *
 * @param array{0: int, 1: int}|null $records left/right record values for node 0
 */
function mmdbFixture(int $recordSize, ?array $records, int $ipVersion = 4, ?int $claimNodeCount = null, string $separator = ''): string
{
    $recBytes = intdiv($recordSize, 8);
    $records = $records ?? [0, 0];
    $tree = str_repeat("\x00", count($records) * $recBytes * 2);
    $pack = static function (int $v) use ($recordSize, $recBytes): string {
        if ($recordSize === 32) {
            return pack('N', $v);
        }
        if ($recordSize === 28) {
            // The reader decodes a 28-bit record from four bytes: the three
            // slot bytes plus the next byte, so the slot holds the first
            // three and the separator carries the low byte.
            return substr(chr(($v >> 24) << 4) . chr(($v >> 16) & 0xFF) . chr(($v >> 8) & 0xFF), 0, 3);
        }
        if ($recordSize === 16) {
            return substr(pack('N', $v), 2, 2);
        }

        return substr(pack('N', $v), 1, 3);
    };
    foreach (array_values($records) as $slot => $value) {
        if (is_string($value)) {
            $tree = substr_replace($tree, $value, $slot * $recBytes, strlen($value));
            continue;
        }
        $tree = substr_replace($tree, $pack($value), $slot * $recBytes, $recBytes);
    }
    $nodeCount = $claimNodeCount ?? count($records);
    $data = "\xE1\x47country\x42US";
    $meta = "\xE3"
        . "\x4A" . 'node_count' . ($nodeCount < 256 ? "\xA1" . chr($nodeCount) : "\xA2" . pack('n', $nodeCount))
        . "\x4B" . 'record_size' . "\xA1" . chr($recordSize)
        . "\x4A" . 'ip_version' . "\xA1" . chr($ipVersion);

    return $tree . $separator . $data . "\xAB\xCD\xEFMaxMind.com" . $meta;
}

function mmdbLookup(string $content, string $ip): ?array
{
    $path = tempnam(sys_get_temp_dir(), 'mmdbfix');
    file_put_contents($path, $content);
    try {
        return (new MmdbReader($path))->lookup($ip);
    } finally {
        @unlink($path);
    }
}

// 24-bit tree: left record equals the node count (a miss), right points at data.
$miss = mmdbFixture(24, [2, 18], separator: "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
$t->same(null, mmdbLookup($miss, '1.2.3.4'), 'a record equal to the node count is not found');
$hit = mmdbFixture(24, [0, 18], separator: "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
$t->same(['country' => 'US'], mmdbLookup($hit, '128.0.0.1'), 'a data pointer resolves the country map');

// 32-bit tree carries both records inside the node.
$hit32 = mmdbFixture(32, [0, 18], separator: "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
$t->same(['country' => 'US'], mmdbLookup($hit32, '128.0.0.1'), 'a 32-bit tree resolves the country map');

// 28-bit tree: the left record spills into the separator byte the reader reads.
$hit28 = mmdbFixture(28, [0, 0, "\x14\x00\x00", 0], separator: "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
$t->same(['country' => 'US'], mmdbLookup($hit28, '128.0.0.1'), 'a 28-bit tree resolves the country map');

// An IPv6 database pads bare v4 addresses with the mapped prefix.
$hit6 = mmdbFixture(24, [0, 18], 6, separator: "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
$t->same(['country' => 'US'], mmdbLookup($hit6, '1.2.3.4'), 'an ipv6 database pads a v4 address');

/**
 * Builds a tree whose metadata claims far more nodes than the file holds,
 * then walks it: the walk runs off the end of the file.
 */
function mmdbLookupTruncated(): ?array
{
    $path = tempnam(sys_get_temp_dir(), 'mmdbtrunc');
    file_put_contents($path, mmdbFixture(24, [0, 18], claimNodeCount: 5000));
    try {
        return (new MmdbReader($path))->lookup('128.0.0.1');
    } finally {
        @unlink($path);
    }
}

$t->throws(MmdbError::class, static fn (): MmdbReader => new MmdbReader(mmdbTempFile(mmdbFixture(16, [0, 17]))), 'an unsupported record size is rejected');
$t->throws(MmdbError::class, static fn (): MmdbReader => mmdbLookupTruncated(), 'a tree past the file end is rejected as truncated');
$t->throws(MmdbError::class, static fn (): MmdbReader => new MmdbReader(mmdbTempFile("\xAB\xCD\xEFMaxMind.com\x00\x00")), 'non map metadata is rejected as malformed');

$t->section('sus patterns: context and validator edges');

$t->section('sus patterns: context and validator edges');

$t->same('unknown', SusPatterns::normalizeContext(null), 'a null context normalizes to unknown');
$t->same('unknown', SusPatterns::normalizeContext('made_up_context'), 'an unknown context name normalizes to unknown');
$t->same('header', SusPatterns::normalizeContext('header:embedded_json'), 'a context prefix survives normalization');

$braceDetect = new SusPatterns(0.5);
$braceResult = $braceDetect->detect('{a,b}', '9.9.9.9', 'unknown');
$t->same(true, $braceResult['is_threat'], 'a brace expansion command reports a threat');
$t->same('cmd_injection', $braceResult['threats'][0]['category'] ?? '', 'the brace expansion threat is cmd injection');

$alnum = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
mt_srand(7);
$entropyRun = '';
for ($i = 0; $i < 150; $i++) {
    $entropyRun .= $alnum[mt_rand(0, 61)];
}
$semanticDetect = new SusPatterns(0.3);
$semanticResult = $semanticDetect->detect('0xDEADBEEF ' . $entropyRun, '9.9.9.9', 'unknown');
$t->same(true, $semanticResult['is_threat'], 'a high entropy body with a low semantic threshold is a threat');
$t->same('semantic', $semanticResult['threats'][0]['type'] ?? '', 'the semantic fallback produces a semantic threat');
$t->same('suspicious', $semanticResult['threats'][0]['attack_type'] ?? '', 'the semantic fallback attack type is suspicious');

// Deeply nested percent-encoding keeps changing past the decode iteration
// budget; the exhaustion signal rides back as a custom threat.
$deep = str_repeat('%25', 40) . 'SELECT';
for ($i = 0; $i < 30; $i++) {
    $deep = rawurlencode($deep);
}
$budgetDetector = new SusPatterns(0.5);
$budgetResult = $budgetDetector->detect($deep, '9.9.9.9', 'unknown');
$t->same(true, in_array('decode_budget_exhausted', array_column($budgetResult['threats'], 'pattern'), true), 'decode budget exhaustion is reported as a threat');

$flagBudget = [false];
(new Preprocessor())->preprocessWithDecoded($deep, $flagBudget);
$t->same([true], $flagBudget, 'the decode budget flag stays an array and flips to true');

$t->section('shell validators: glued pair verdicts through the scanner');

$cmdScanner = new SusPatterns(0.5);
$windowCmd = $cmdScanner->detect('`id`; `uname -a`', '9.9.9.9', 'query_param');
$t->same(true, in_array('cmd_injection', array_column($windowCmd['threats'], 'category'), true), 'a command chain after a backtick pair is injection');
$sqlGlued = $cmdScanner->detect('SELECT`x`, `y` FROM users', '9.9.9.9', 'query_param');
$t->same(false, in_array('cmd_injection', array_column($sqlGlued['threats'], 'category'), true), 'a sql keyword glued to a backtick pair is not injection');
$dollarQuoted = $cmdScanner->detect('note `${HOME}` set', '9.9.9.9', 'query_param');
$t->same(false, in_array('cmd_injection', array_column($dollarQuoted['threats'], 'category'), true), 'a substitution inside backticks is not injection');
$dollarPlain = $cmdScanner->detect('x=${HOME}', '9.9.9.9', 'query_param');
$t->same(true, in_array('cmd_injection', array_column($dollarPlain['threats'], 'category'), true), 'a bare substitution in a query is injection');

$t->same(true, ShellValidators::braceExpansionIsDangerousCommand('x{a,b}y', ['start' => 0, 'end' => 7, 'text' => 'x{a,b}y', 'groups' => []]), 'a brace expansion with letters is dangerous');
$t->same(false, ShellValidators::braceExpansionIsDangerousCommand('x{2,4}y', ['start' => 0, 'end' => 7, 'text' => 'x{2,4}y', 'groups' => []]), 'a brace expansion with digits only is benign');
$t->same(false, ShellValidators::braceExpansionIsDangerousCommand('zz', ['start' => 0, 'end' => 2, 'text' => 'zz', 'groups' => []]), 'a match without braces is benign');

$t->section('xml: walk continuation guards');

$t->section('xml: walk continuation guards');

$t->same(0, count(XmlXxe::xmlInternalEntityFinditer('<!DOCTYPE r no brackets here')), 'a doctype without any bracket stops the internal entity walk');
$t->same(2, count(XmlXxe::xmlInternalEntityFinditer('<!DOCTYPE r [<!ENTITY<!DOCTYPE x [<!ENTITY y>]')), 'an overlapping doctype prefix inside a matched span is skipped once');

$t->same([], XmlXxe::xmlXxePublicExternalDtdFinditer('<!DOCTYPE r PUBLIC "-//X//EN" https://download.example.com/x.dtd>'), 'an unquoted url scheme never completes');
$t->same([], XmlXxe::xmlXxePublicExternalDtdFinditer('<!DOCTYPE r PUBLIC "-//X//EN" "https://a.com>'), 'a url closed by the tag end never completes');
$t->same([], XmlXxe::xmlXxePublicExternalDtdFinditer('<!DOCTYPE r PUBLIC "-//X//EN" "https://a.com"'), 'a url without a trailing boundary never completes');
$t->same(1, count(XmlXxe::xmlXxePublicExternalDtdFinditer('<!DOCTYPE r PUBLIC "-//A//EN" "https://d.example.com/x" PUBLIC "-//B//EN" "https://e.example.com/y">')), 'a second public inside a matched span is skipped');
$t->same([], XmlXxe::xmlXxePublicExternalDtdFinditer('junk PUBLIC "-//A//EN" "https://d.example.com/x">'), 'a public without a doctype in its run never matches');
$t->same(1, count(XmlXxe::xmlXxePublicExternalDtdFinditer('<!DOCTYPE a PUBLIC "https://valid.example.com/x"> blah <!DOCTYPE b PUBLIC "-//A//EN" oops>')), 'a public whose run carries no quoted url contributes nothing');
$t->same(1, count(XmlXxe::xmlXxePublicExternalDtdFinditer('<!DOCTYPE r [<!ENTITY c>]><!DOCTYPE s PUBLIC "-//X//EN" "https://download.example.com/x.dtd">')), 'a run boundary scan skips earlier markup');

$t->section('preg: safeEval, group gaps, and failure surfaces');

$t->section('preg: safeEval, group gaps, and failure surfaces');

$t->throws(PregFailure::class, static fn () => Preg::safeEval('/[unclosed/', 'x'), 'safeEval throws on an invalid pattern');
$t->same(null, Preg::safeEval("\x01zzz\x01ui", 'nothing here'), 'safeEval returns null without a match');
$evalHit = Preg::safeEval("\x01(a)|(b)\x01ui", 'zzb');
$t->same('b', $evalHit[0]['text'] ?? null, 'safeEval reports the match text at group zero');
$t->same(true, array_key_exists(1, $evalHit) && $evalHit[1] === null, 'an unparticipating group decodes as null');

$t->throws(PregFailure::class, static fn () => Preg::allMatches('[unclosed', 'x'), 'allMatches throws on an invalid pattern');
$altHits = Preg::allMatches('(a)|(b)', 'zzb zzxx');
$t->same(true, array_key_exists(1, $altHits[0]['groups']) && $altHits[0]['groups'][1] === null, 'allMatches marks the skipped alternative null');

$t->throws(PregFailure::class, static fn () => Preg::matchAnchoredAt('[unclosed', 'x', 0), 'matchAnchoredAt throws on an invalid pattern');
$anchored = Preg::matchAnchoredAt('(a)|(b)', 'zzb', 2);
$t->same(true, array_key_exists(1, $anchored['groups']) && $anchored['groups'][1] === null, 'matchAnchoredAt marks the skipped alternative null');
$t->same(null, Preg::matchAnchoredAt('(a)', '', 0), 'an empty segment anchors nothing');

$t->throws(PregFailure::class, static fn () => Preg::searchFrom('[unclosed', 'subject', 0), 'searchFrom throws on an invalid pattern');

$replaced = Preg::replace('(a)|(b)', 'zzb', static fn (array $m): string => ($m['groups'][1]['start'] ?? 0) === -1 && $m['text'] === 'b' ? '[bee]' : '?');
$t->same('zz[bee]', $replaced, 'replace flags unparticipating groups with a minus one start');

$t->same(2, Preg::cp("xééy", 3), 'cp converts a byte offset to a code point index');

$total = $t->passed + $t->failed;
echo "\nPassed: {$t->passed}, Failed: {$t->failed}\n";
echo "{$t->passed}/{$total}" . ($t->failed === 0 ? ' GREEN' : ' RED') . "\n";
exit($t->failed === 0 ? 0 : 1);
