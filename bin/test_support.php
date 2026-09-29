<?php

/**
 * Unit-edge suite for the Support and Detection primitives (regex helpers,
 * legacy-IP decoding, the pickle VM, XXE matchers, truncation, base64).
 * Coverage gating lives in .github/coverage-runner.php; this suite only
 * asserts behavior.
 */

declare(strict_types=1);

use RenzoFranceschini\GuardCore\Detection\Base64;
use RenzoFranceschini\GuardCore\Detection\Preprocessor;
use RenzoFranceschini\GuardCore\Detection\Semantic;
use RenzoFranceschini\GuardCore\Ip\CanonicalIp;
use RenzoFranceschini\GuardCore\Detection\LdapIpv4;
use RenzoFranceschini\GuardCore\Detection\Pickle;
use RenzoFranceschini\GuardCore\Detection\Preg;
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

$total = $t->passed + $t->failed;
echo "\nPassed: {$t->passed}, Failed: {$t->failed}\n";
echo "{$t->passed}/{$total}" . ($t->failed === 0 ? ' GREEN' : ' RED') . "\n";
exit($t->failed === 0 ? 0 : 1);
