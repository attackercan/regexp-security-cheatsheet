<?php
	#Author: Vladimir Ivanov
	#Twitter: @httpsonly

set_time_limit(0);

	#Settings for debug (var_dump)
ini_set('xdebug.var_display_max_depth', 5);
ini_set('xdebug.var_display_max_children', 256);
ini_set('xdebug.var_display_max_data', 1024);

	#CLI Interface parameters
$options = getopt("", array("file::", "regexp::", "output::"));
$options['file']	 = $_GET['file'];

if(!@$options)
	echo "RegExp security finder.\r\n\r\nUsage examples:\r\nphp script.php --regexp=\"(.*?){1,5}\"\r\nphp script.php --file=\"input.txt\"\r\nphp script.php --file=\"input.txt\" --output \"output.html\"\r\n\r\nBy default output is saved as output_FILENAME_HHMMSS_DDMMYY.html\r\n\r\n";

if((!@$options['regexp'] && !@$options['file']) || ((@$options['regexp'] && @$options['file'])))
	die(">>> ERROR! Input --regexp OR --file!\r\n");

if(@$options['file'])
	$file = file($options['file']);
else
	$file = array($options['regexp']);

if(!@$options['output'])
	$output_filename = "output_".preg_replace("/[^a-z0-9]/i", "_", @$options['file'])."_".date("His_dmy").".html";
else
	$output_filename = $options['output'];



	#Available Rules ( https://github.com/attackercan/regexp-fundamental-requirements )
	#Feel free to comment rules which cause false positives, e.g. 3, 7
	
$rules = array(
	'Rule 1 (Regexp should avoid using metacharacters for start and end of a string. It is possible to bypass regexp by inserting any symbol in front or after regexp)'
		=> '/(?:^|[^\[\\\])(\^|\\\A|\$|\\\Z)/',
		
	'Rule 2'		// TODO
		=> '//',	// Responsible for checking if regexp is case-insensitive
		
		/*
	'Rule 3 (Regexp should avoid using dot "." symbol, which means every symbol except newline (\n). It is possible to bypass regexp using newline injection).'
		=> '/[^\\\](\.\+)/',  // Lots of false positives
		*/
		
	'Rule 4 (Regexp is possibly vulnerable to ReDoS).'
		=> '/(\((?:[\(\[]?)[^(]*?(?:[\)\]]?)[^\x5c][+*](?:[^\)\]]*)\)[+*])/',
		
	'Rule 5 (Number of repetitions of set or group {} should be carefully used, as one can bypass such limitation by lowering or increasing specified numbers).'
		// =>  '/(\{[\d,].*?\})/', // Default rule
		=> '/(?:(?!\\{0,\\}|\\{1,\\}|\\{0,1\\}))(\\{\d*,\d*\\})/',  // This fixes False positives on Comodo WAF - no {0,}  {1,}  {0,1}  -- analogues for *  +  ?

	'Rule 6 (Ranges except a-zA-Za-f0-9)'
		=> '/\[[^\]]*(?!A-Z|a-z|A-F|a-f|0-9)(\w{1}-(?:\w|\\\){1}).*?\]/',
		
		/*
	'Rule 7 (Regexp should likely use plus + metacharacter in places where it is necessary, as it means "one or more". Alternative metacharacter star "*", which means "zero or more" is generally preferred.)'
		=> '/(\\\[a-z][+])/i', // Generates lots of false positives - manual check is needed in paranoid mode
		
	'Rule 8 (Usage of wildcards should be reasonable. \r\n characters can often be bypassed by either substitution, or by using newline alternative \v, \f and others).'
		=> '/(\\\a|\[[^\]]*?\\\b[^\[]*?\]|\\\t|\\\r|\\\v|\\\f|\\\n)/',  // Is partly covered by other rules - manual check is needed in paranoid mode
		*/
		
	'Rule 9'		// TODO
		=> '//',	// Responsible for applying regexp to right scope of inputs
		
	'Rule 10 (Regular expression writers should be careful while using only whitespace character (%20) for separating tag attributes. Rule can be bypassed with alternatives, i.e. newline character %0d,%0a).'
		=> '/(\[[^\]]*?\s[^\]]*?\])/',

	'Rule 11 (Nonstandard combinations of operators ||).'
		=> '/[^\\\](\|\|)/',
	
	'Rule 12 (Special cases: whitespaces before operators).'
		=> '/( \||\| )/',
	
	'Rule 13 (Usage of wrong syntax in POSIX character classes).'
		=> '/\[.{0,5}(alnum|alpha|ascii|blank|cntrl|digit|graph|lower|print|punct|space|upper|word|xdigit).{0,5}\]/',
	
	'Rule 14 (Opposite usage of brackets [], () and {}).'
		=> '//',	//TODO
	
	'Rule 15 (Re-check backlinks).'
		=> '/(\\\\\d)/',
	
	'Rule 16 (Unsafe usage of comments?).'
		=> '/(\(\?\#)/',
	
	'Rule 17 (Excessive usage of metacharacters in []).'
		=> '//',	//TODO
	
	'Rule 18 (Rarely used wildcards - all wildcards except A,Z,b,r,n,t,wW,sS,dD,u,x).'
		=> '/(\\\(?:B|C|E|G|H|K|L|N|P|Q|R|U|V|X|a|c|e|f|g|h|k|l|o|p|v|z))/',
	
	'Rule 19 (Excessive escaping, e.g. escaping symbol which is not a wildcard).'
		=> '/(\\\(?:F|I|J|M|O|T|Y|i|j|m|q|y))/',
	
	'Rule 20 (Unsafe usage of recursion or IF statements).'
		=> '//',	//TODO

	'Rule 21 (Wrong usage of ranges).'
		=> '/\[.{0,10}(\\\\w{1}-\w{1}).{0,10}\]/',

	/*
		Experimental rules (probably to be removed)
		
	'Rule 11 (While greediness itself does not create bypasses, bad implementation of regexp Greediness can raise False Positive rate).'
		=> '/[^\\\](\.[\+|\*])[^\?]/',
		
	*/
	
	'//'	// Empty string for debug
);

init();

function init() {
	$alerts = 0;
	$HTMLoutput = headHTML();

	foreach($GLOBALS['file'] as $string_id => $string) {
		$string = trim($string);
		$string = str_replace('<', '&lt;', $string);	// Fix for beautiful HTML output
	
		$results_for_string = applyAllRules($string);

		foreach($results_for_string as $rule_name => $matchArrayData) {
			
			if($highlighedString = drawMistakes($string, $matchArrayData)) {
				
				$HTMLoutput .= "Line ".$string_id." => <pre>".$highlighedString."</pre>".$rule_name."<hr>\r\n\r\n";
				$alerts++;
			}
		}
	}

	$HTMLoutput .= "</body></html>";
	file_put_contents($GLOBALS['output_filename'], $HTMLoutput);
	echo "Done!\r\nOutput file is saved as:\r\n".str_replace(basename(__FILE__), $GLOBALS['output_filename'], __FILE__)."\r\n";
	echo "\r\nTotal alerts:". $alerts;
}

function applyAllRules($string) {
	$results = array();
	
	foreach($GLOBALS['rules'] as $name => $rule) {
		$result = applyRule($rule, $string);
		
		// if(!empty($result[0]))
			$results[$name] = $result;
	}
	
	return $results;
}

function applyRule($rule, $string) {
	preg_match_all($rule, $string, $match, PREG_OFFSET_CAPTURE);
	
	if(!empty($match))
		return $match;
	else
		return false;
}

function drawMistakes($string, $matches) {
	$res = $string;
	
	if(!@$matches[1])
		return false;
	
	foreach(array_reverse($matches[1]) as $match) {	// Do substr in reverse order so offsets will not brake
		$res = drawOneMistake($res, $match);
	}
	
	return $res;
}

function drawOneMistake($string, $one_match) {
	
	$offset = $one_match[1];
	$length = strlen($one_match[0]);
	
	if(($real_offset = $offset-$length+1) < $offset) $real_offset = $offset;	// omg, maths!
	
	$before	= substr($string, 0, $real_offset);
	$match	= substr($string, $offset, $length);
	$after	= substr($string, $offset+$length);
	
	$res = $before."<mark><font color='red'>".$match."</font></mark>".$after;	// Use font size=3 or other markup
	
	return $res;
}

function headHTML() {

	return "<html>
		<head>
		<style>
		/*
		<pre> tags wrapping 
		http://www.longren.io/wrapping-text-inside-pre-tags/
		*/

		pre {
		 white-space: pre-wrap;       /* css-3 */
		 white-space: -moz-pre-wrap !important;  /* Mozilla, since 1999 */
		 white-space: -pre-wrap;      /* Opera 4-6 */
		 white-space: -o-pre-wrap;    /* Opera 7 */
		 word-wrap: break-word;       /* Internet Explorer 5.5+ */
		 width: 99%;
		}
		</style>
		</head>
		<body>
";

}

?>