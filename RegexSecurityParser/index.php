<?php

	#Author: Vladimir Ivanov
	#Twitter: @httpsonly

	#Settings for debug (var_dump)
ini_set('xdebug.var_display_max_depth', 5);
ini_set('xdebug.var_display_max_children', 256);
ini_set('xdebug.var_display_max_data', 1024);

	#CLI Interface parameters
$options = getopt("", array("file::", "regexp::", "output::"));

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
	#Feel free to comment rules which cause false positives, e.g. 3, 7, 11
$rules = array(
	'Rule 1 (Regexp should avoid using metacharacters for start and end of a string. It is possible to bypass regexp by inserting any symbol in front or after regexp)'
		=> '/(?:^|[^\[\\\])(\^|\\\A|\$|\\\Z)/',
		
	'Rule 2'		// Currently not present
		=> '//',	// Responsible for checking if regexp is case-insensitive
		
	'Rule 3 (Regexp should avoid using dot "." symbol, which means every symbol except newline (\n). It is possible to bypass regexp using newline injection).'
		=> '/[^\\\](\.\+)/',
		
	'Rule 4 (Regexp is possibly vulnerable to ReDoS).'
		=> '/(\((?:[\(\[]?)[^(]*?(?:[\)\]]?)[^\x5c][+*](?:[^\)\]]*)\)[+*])/',
		
	'Rule 5 (Number of repetitions of set or group {} should be carefully used, as one can bypass such limitation by lowering or increasing specified numbers).'
		=>  '/(\{[\d,].*?\})/',
		
	'Rule 6'		// Currently not present
		=> '//',	// Responsible for checking that regexps don't use t:urlDecode (t:urlDecodeUni instead)
		
	'Rule 7 (Regexp should likely use plus + metacharacter in places where it is necessary, as it means "one or more". Alternative metacharacter star "*", which means "zero or more" is generally preferred.)'
		=> '/(\\\[a-z][+])/i',
		
	'Rule 8 (Usage of wildcards should be reasonable. \r\n characters can often be bypassed by either substitution, or by using newline alternative \v, \f and others).'
		=> '/(\\\a|\[[^\]]*?\\\b[^\[]*?\]|\\\t|\\\r|\\\v|\\\f|\\\n)/',
		
	'Rule 9'		// Currently not present
		=> '//',	// Responsible for applying regexp to right scope of inputs
		
	'Rule 10 (Regular expression writers should be careful while using only whitespace character (%20) for separating tag attributes. Rule can be bypassed with alternatives, i.e. newline character %0d,%0a).'
		=> '/(\[[^\]]*?\s[^\]]*?\])/',
		
	'Rule 11 (While greediness itself does not create bypasses, bad implementation of regexp Greediness can raise False Positive rate).'
		=> '/[^\\\](\.[\+|\*])[^\?]/',
	
	'//'	// Empty string for debug
);

init();

function init() {
	$HTMLoutput = headHTML();

	foreach($GLOBALS['file'] as $string_id => $string) {
		$string = trim($string);
		$string = str_replace('<', '&lt;', $string);	// Fix for beautiful HTML output
	
		$results_for_string = applyAllRules($string);

		foreach($results_for_string as $rule_name => $matchArrayData) {
			
			if($highlighedString = drawMistakes($string, $matchArrayData)) {
				
				$HTMLoutput .= "Line ".$string_id." => <pre>".$highlighedString."</pre>".$rule_name."<hr>\r\n\r\n";
				
			}
		}
	}

	$HTMLoutput .= "</body></html>";
	file_put_contents($GLOBALS['output_filename'], $HTMLoutput);
	echo "Done!\r\nOutput file is saved as:\r\n".str_replace(basename(__FILE__), $GLOBALS['output_filename'], __FILE__)."\r\n";
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
